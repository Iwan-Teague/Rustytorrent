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

/// Spawn the plain-disk storage task, preallocating every file in the layout.
///
/// This is the unconditional entry point used by callers that always want the
/// full layout on disk (e.g. the `decrypt` subcommand). For selective
/// download, see [`spawn_storage_task_selective`].
pub fn spawn_storage_task(
    layout: Layout,
    cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> tokio::task::JoinHandle<()> {
    spawn_storage_task_selective(layout, None, cmd_rx, event_tx)
}

/// Spawn the plain-disk storage task with an optional selective-allocation
/// mask.
///
/// `wanted_files`, when `Some`, is a mask parallel to `layout.files`: a
/// `false` entry means that file receives **zero** bytes from any wanted
/// piece (selective download), so it is never created or preallocated on
/// disk. `None` preserves the original behaviour (allocate every file). The
/// write path never targets a skipped file — it is guaranteed unreferenced
/// because `wanted_files` is derived from the same piece→file span mapping
/// `write_piece` uses, so a skipped file cannot appear in any wanted piece's
/// slices.
pub fn spawn_storage_task_selective(
    layout: Layout,
    wanted_files: Option<Vec<bool>>,
    cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_storage(layout, wanted_files, cmd_rx, event_tx.clone()).await {
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
    wanted_files: Option<Vec<bool>>,
    mut cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> Result<()> {
    // Pre-allocate every file in the layout — except files that receive no
    // bytes from any wanted piece under selective download, which we skip
    // entirely (no create, no set_len). A skipped file is represented by a
    // `None` slot: the write/read paths must never index it, which holds
    // because `wanted_files` and the slice mapping share the same span data.
    let mut files: Vec<Option<File>> = Vec::with_capacity(layout.files.len());
    for (i, span) in layout.files.iter().enumerate() {
        // Skip only when a mask is present AND this file is marked unwanted.
        // Absence of a mask (the default, non-selective path) allocates all.
        let skip = wanted_files
            .as_ref()
            .map(|w| !w.get(i).copied().unwrap_or(true))
            .unwrap_or(false);
        if skip {
            files.push(None);
            continue;
        }
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
        files.push(Some(f));
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

/// Borrow the open `File` at `file_idx`, or error if it was skipped
/// (selective download left it unallocated). A wanted piece never references
/// a skipped file — both sides come from the same span mapping — so this
/// error is a defensive guard, not an expected path, kept instead of an
/// `unwrap` to honour the no-panic rule.
fn file_at(files: &mut [Option<File>], file_idx: usize) -> Result<&mut File> {
    files
        .get_mut(file_idx)
        .and_then(|slot| slot.as_mut())
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("storage: file {file_idx} skipped (selective download) but a piece referenced it"),
            ))
        })
}

async fn write_piece(
    layout: &Layout,
    files: &mut [Option<File>],
    index: usize,
    data: &[u8],
) -> Result<()> {
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
        let f = file_at(files, file_idx)?;
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
        file_at(files, file_idx)?.flush().await?;
    }
    Ok(())
}

async fn read_range(
    layout: &Layout,
    files: &mut [Option<File>],
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
        let f = file_at(files, file_idx)?;
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
    // Open every output file, tolerating ones that don't exist. A selective
    // (`--select`) download deliberately never creates fully-unwanted files,
    // and a partially-downloaded multi-file torrent may not have created
    // every file yet. A missing file is not fatal to the whole scan — we
    // simply can't verify the pieces that read from it, so we skip those and
    // still resume every piece whose files are all present. (Previously a
    // single missing file abandoned the entire resume, so `--select` resumed
    // nothing and re-verified/re-downloaded completed files on every restart.)
    let mut files: Vec<Option<File>> = Vec::with_capacity(layout.files.len());
    for span in &layout.files {
        match File::open(&span.path).await {
            Ok(f) => files.push(Some(f)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => files.push(None),
            Err(e) => return Err(Error::Io(e)),
        }
    }
    // Pipelined scan: read each piece serially (file-cursor order), but spawn
    // SHA-1 on a blocking thread *without immediately awaiting* it — the hash
    // for piece N runs while we read piece N+1 from disk, overlapping CPU and
    // I/O. A sliding window caps the number of in-flight piece buffers so peak
    // memory stays bounded even on torrents with thousands of pieces.
    const MAX_IN_FLIGHT: usize = 32;
    // `(piece_index, JoinHandle<bool>)` — ordered by insertion so the final
    // drain preserves piece order.
    let mut in_flight: std::collections::VecDeque<(usize, tokio::task::JoinHandle<bool>)> =
        std::collections::VecDeque::with_capacity(MAX_IN_FLIGHT);
    let mut out = Vec::new();

    /// Drain one finished hash from the front of `in_flight` and record it.
    async fn drain_one(
        in_flight: &mut std::collections::VecDeque<(usize, tokio::task::JoinHandle<bool>)>,
        out: &mut Vec<usize>,
    ) {
        if let Some((idx, handle)) = in_flight.pop_front() {
            if handle.await.unwrap_or(false) {
                out.push(idx);
            }
        }
    }

    for (index, expected) in piece_hashes.iter().enumerate().take(layout.num_pieces) {
        // Drain the oldest in-flight hash before reading the next piece
        // once the window is full — bounds peak memory to
        // MAX_IN_FLIGHT × max_piece_size.
        if in_flight.len() >= MAX_IN_FLIGHT {
            drain_one(&mut in_flight, &mut out).await;
        }

        let psz = piece_size(layout, index);
        let slices = layout.slices_for_piece(index, psz);
        let mut buf = vec![0u8; psz as usize];
        let mut off = 0usize;
        let mut ok = true;
        for (file_idx, file_off, count) in slices {
            // A slice into a file that isn't on disk (selective-skipped or
            // not yet created) can't be verified → this piece isn't resumable.
            let Some(f) = files[file_idx].as_mut() else {
                ok = false;
                break;
            };
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
            // Spawn the hash without awaiting — it runs on a blocking thread
            // while the next piece is being read from disk, overlapping
            // CPU-bound SHA-1 with async I/O. (Reads already don't block the
            // reactor; moving the await out of the loop is the key change.)
            let expected = *expected;
            let handle =
                tokio::task::spawn_blocking(move || crate::piece::verify_piece(&buf, &expected));
            in_flight.push_back((index, handle));
        }
    }

    // Drain all remaining in-flight hashes.
    while !in_flight.is_empty() {
        drain_one(&mut in_flight, &mut out).await;
    }

    // Results are in piece-index order because we drain oldest-first and
    // push to `out` in drain order. The engine relies on the returned indices
    // being valid piece indices but not on them being sorted; sort anyway for
    // determinism and to match the old behaviour.
    out.sort_unstable();
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
        // pid + nanos + a process-wide counter so parallel test threads can't
        // collide on the same dir when the clock resolution is coarse.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustytorrent-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn scan_resume_tolerates_missing_file() {
        use sha1::{Digest, Sha1};
        let tmp = tempdir();
        // Three 100-byte files at piece_length 100 → one piece per file.
        let t = make_torrent_multi(100, vec![(100, "a.txt"), (100, "b.txt"), (100, "c.txt")]);
        let layout = Layout::from_torrent(tmp.clone(), &t);
        let data: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i + 1; 100]).collect();
        // Real per-piece hashes (piece i == file i, file-aligned).
        let hashes: Vec<[u8; 20]> = data
            .iter()
            .map(|d| {
                let mut h = [0u8; 20];
                h.copy_from_slice(&Sha1::digest(d));
                h
            })
            .collect();
        // Write files 0 and 2; file 1 (b.txt) is intentionally absent, as a
        // selective-skipped (or not-yet-created) file would be on resume.
        tokio::fs::create_dir_all(layout.files[0].path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&layout.files[0].path, &data[0])
            .await
            .unwrap();
        tokio::fs::write(&layout.files[2].path, &data[2])
            .await
            .unwrap();
        let resumed = scan_resume(&layout, &hashes).await.unwrap();
        // Pieces 0 and 2 resume; piece 1 (missing file) is skipped. The scan
        // must NOT bail to empty just because one file is absent.
        assert_eq!(resumed, vec![0, 2]);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
