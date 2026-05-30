use std::io::SeekFrom;

use tokio::fs::File;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::storage::layout::Layout;

#[derive(Debug)]
pub enum StorageCommand {
    Write {
        index: u32,
        data: Vec<u8>,
    },
    Read {
        index: u32,
        begin: u32,
        length: u32,
        reply: mpsc::Sender<Result<Vec<u8>>>,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum StorageEvent {
    Written { index: u32 },
    Error { index: Option<u32>, msg: String },
}

pub fn spawn_storage_task(
    layout: Layout,
    cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_storage(layout, cmd_rx, event_tx.clone()).await {
            let _ = event_tx
                .send(StorageEvent::Error {
                    index: None,
                    msg: e.to_string(),
                })
                .await;
        }
    })
}

async fn run_storage(
    layout: Layout,
    mut cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> Result<()> {
    // Pre-allocate every file in the layout.
    let mut files: Vec<File> = Vec::with_capacity(layout.files.len());
    for span in &layout.files {
        if let Some(parent) = span.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&span.path)
            .await?;
        // Sparse-allocate up to the file length.
        let cur = f.metadata().await?.len();
        if cur < span.length {
            f.set_len(span.length).await?;
        }
        files.push(f);
    }

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            StorageCommand::Shutdown => break,
            StorageCommand::Write { index, data } => {
                if let Err(e) = write_piece(&layout, &mut files, index as usize, &data).await {
                    let _ = event_tx
                        .send(StorageEvent::Error {
                            index: Some(index),
                            msg: e.to_string(),
                        })
                        .await;
                } else {
                    let _ = event_tx.send(StorageEvent::Written { index }).await;
                }
            }
            StorageCommand::Read {
                index,
                begin,
                length,
                reply,
            } => {
                let res = read_range(&layout, &mut files, index, begin, length).await;
                let _ = reply.send(res).await;
            }
        }
    }
    Ok(())
}

async fn write_piece(layout: &Layout, files: &mut [File], index: usize, data: &[u8]) -> Result<()> {
    let piece_size = piece_size(layout, index);
    if data.len() as u64 != piece_size {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "write piece {index}: data {} != expected {}",
                data.len(),
                piece_size
            ),
        )));
    }
    let slices = layout.slices_for_piece(index, piece_size);
    let mut data_off: usize = 0;
    // Track which files this piece touched (slices are in file order, so a
    // last-element check dedups) to flush exactly those without recomputing
    // the slice mapping a second time.
    let mut touched: Vec<usize> = Vec::new();
    for (file_idx, file_off, count) in slices {
        let f = &mut files[file_idx];
        f.seek(SeekFrom::Start(file_off)).await?;
        f.write_all(&data[data_off..data_off + count as usize])
            .await?;
        data_off += count as usize;
        if touched.last() != Some(&file_idx) {
            touched.push(file_idx);
        }
    }
    // Flush after every piece — safer than buffering and losing on crash.
    for file_idx in touched {
        files[file_idx].flush().await?;
    }
    Ok(())
}

async fn read_range(
    layout: &Layout,
    files: &mut [File],
    index: u32,
    begin: u32,
    length: u32,
) -> Result<Vec<u8>> {
    let piece_size = piece_size(layout, index as usize);
    let end = (begin as u64) + (length as u64);
    if end > piece_size {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "read past piece end",
        )));
    }
    let global_start = (index as u64) * layout.piece_length + begin as u64;
    let slices = layout.slices(global_start, length as u64);
    let mut out = vec![0u8; length as usize];
    let mut out_off: usize = 0;
    for (file_idx, file_off, count) in slices {
        let f = &mut files[file_idx];
        f.seek(SeekFrom::Start(file_off)).await?;
        f.read_exact(&mut out[out_off..out_off + count as usize])
            .await?;
        out_off += count as usize;
    }
    Ok(out)
}

fn piece_size(layout: &Layout, index: usize) -> u64 {
    if index + 1 == layout.num_pieces {
        let r = layout.total_length % layout.piece_length;
        if r == 0 {
            layout.piece_length
        } else {
            r
        }
    } else {
        layout.piece_length
    }
}

/// On-startup resume scan: SHA1-verify every piece against expected hashes
/// and return the indices of complete pieces.
pub async fn scan_resume(layout: &Layout, piece_hashes: &[[u8; 20]]) -> Result<Vec<usize>> {
    let mut files: Vec<File> = Vec::with_capacity(layout.files.len());
    let mut any_missing = false;
    for span in &layout.files {
        match File::open(&span.path).await {
            Ok(f) => files.push(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                any_missing = true;
                break;
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    if any_missing {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (index, expected) in piece_hashes.iter().enumerate().take(layout.num_pieces) {
        let psz = piece_size(layout, index);
        let slices = layout.slices_for_piece(index, psz);
        let mut buf = vec![0u8; psz as usize];
        let mut off = 0usize;
        let mut ok = true;
        for (file_idx, file_off, count) in slices {
            let f = &mut files[file_idx];
            if f.seek(SeekFrom::Start(file_off)).await.is_err() {
                ok = false;
                break;
            }
            if f.read_exact(&mut buf[off..off + count as usize])
                .await
                .is_err()
            {
                ok = false;
                break;
            }
            off += count as usize;
        }
        if ok {
            // SHA-1 is CPU-bound; running it inline here would block the
            // tokio reactor for the whole resume scan (a multi-second
            // freeze on a large torrent at cold start). Offload the hash
            // to the blocking pool — the buffer is owned so it moves in
            // cleanly. (Reads above are already async.)
            let expected = *expected;
            let matched =
                tokio::task::spawn_blocking(move || crate::piece::verify_piece(&buf, &expected))
                    .await
                    .unwrap_or(false);
            if matched {
                out.push(index);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::metainfo::{FileEntry, Info, TorrentFile, TorrentFiles};

    fn make_torrent_multi(piece_length: u64, files: Vec<(u64, &str)>) -> TorrentFile {
        let total: u64 = files.iter().map(|(l, _)| *l).sum();
        let num_pieces = total.div_ceil(piece_length) as usize;
        TorrentFile {
            info_hash: [0u8; 20],
            announce: None,
            announce_list: vec![],
            info: Info {
                name: "pkg".into(),
                piece_length,
                piece_hashes: vec![[0u8; 20]; num_pieces],
                files: TorrentFiles::Multi {
                    files: files
                        .into_iter()
                        .map(|(l, p)| FileEntry {
                            length: l,
                            path: p.into(),
                        })
                        .collect(),
                },
                private: false,
            },
        }
    }

    #[tokio::test]
    async fn write_and_read_multi_file() {
        let tmp = tempdir();
        let t = make_torrent_multi(100, vec![(150, "a.txt"), (100, "b.txt"), (50, "c.txt")]);
        let layout = Layout::from_torrent(tmp.clone(), &t);

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (ev_tx, mut ev_rx) = mpsc::channel(16);
        let handle = spawn_storage_task(layout.clone(), cmd_rx, ev_tx);

        // Piece 1 = bytes 100..200 across files a.txt[100..150] + b.txt[0..50].
        let piece1: Vec<u8> = (0..100).map(|i| (i as u8).wrapping_add(50)).collect();
        cmd_tx
            .send(StorageCommand::Write {
                index: 1,
                data: piece1.clone(),
            })
            .await
            .unwrap();
        match ev_rx.recv().await.unwrap() {
            StorageEvent::Written { index } => assert_eq!(index, 1),
            ev => panic!("unexpected event {ev:?}"),
        }
        // Read it back: range begin=0, length=100, piece 1.
        let (rt, mut rr) = mpsc::channel(1);
        cmd_tx
            .send(StorageCommand::Read {
                index: 1,
                begin: 0,
                length: 100,
                reply: rt,
            })
            .await
            .unwrap();
        let back = rr.recv().await.unwrap().unwrap();
        assert_eq!(back, piece1);

        cmd_tx.send(StorageCommand::Shutdown).await.unwrap();
        let _ = handle.await;

        // Files exist on disk with right sizes.
        for f in &layout.files {
            let md = std::fs::metadata(&f.path).unwrap();
            assert_eq!(md.len(), f.length);
        }

        // a.txt[100..150] should match first 50 bytes of piece1.
        let a = std::fs::read(&layout.files[0].path).unwrap();
        assert_eq!(&a[100..150], &piece1[0..50]);
        let b = std::fs::read(&layout.files[1].path).unwrap();
        assert_eq!(&b[0..50], &piece1[50..100]);
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustytorrent-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
