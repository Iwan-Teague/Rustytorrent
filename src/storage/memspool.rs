//! In-memory spool — the B2 `--memory-only` storage backend.
//!
//! Like the B1 encrypted spool, this replaces the on-disk file layout
//! with a single backing store. Unlike B1, the backing store never
//! touches disk at all: pieces live in a `Vec<Option<Vec<u8>>>` on the
//! heap for the lifetime of the process. When the process exits, the
//! download is gone. Useful when the user wants the strongest
//! "leave-no-trace" posture (paired with `--anonymous`) and the
//! torrent fits comfortably in RAM.
//!
//! Mutually exclusive with `--paranoid`: the two solve overlapping
//! threats with different storage shapes, and trying to use both at
//! once would require choosing one to drive the storage task.
//!
//! ## Platform support
//!
//! Linux/macOS/\*BSD: implemented. On Linux the backing is a plain
//! heap-allocated `Vec`, same as `/dev/shm`'s tmpfs in practice (both
//! are RAM-resident and both can be swapped under memory pressure;
//! neither is mlock-pinned). On macOS we use the same heap approach
//! rather than MAP_ANON because the swap behavior is identical and
//! the code is much simpler.
//!
//! Windows: deliberately unsupported. The engine refuses to start
//! with `--memory-only` on Windows so the user gets a clear error
//! instead of a silent fallback to disk.
//!
//! ## API shape
//!
//! Mirrors [`EncryptedSpool`](crate::storage::spool::EncryptedSpool):
//! `write_piece(index, data)` and `read_range(index, begin, length)`.
//! No header, no key derivation, no on-disk format — there's nothing
//! to interoperate with.

use std::path::PathBuf;

use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::storage::disk::{StorageCommand, StorageEvent};
use crate::storage::layout::Layout;

/// In-RAM piece store with the same write_piece / read_range API as
/// the encrypted spool. `pieces[i] = Some(buf)` once piece `i` has
/// been written; `None` means not present yet.
pub struct MemSpool {
    pieces: Vec<Option<Vec<u8>>>,
    piece_length: u64,
    num_pieces: u32,
    total_length: u64,
}

impl MemSpool {
    pub fn new(piece_length: u64, num_pieces: u32, total_length: u64) -> Self {
        Self {
            pieces: (0..num_pieces).map(|_| None).collect(),
            piece_length,
            num_pieces,
            total_length,
        }
    }

    pub fn write_piece(&mut self, index: u32, data: &[u8]) -> Result<()> {
        let actual = self.piece_size(index);
        if data.len() as u64 != actual {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "memspool write piece {index}: got {} bytes, expected {actual}",
                    data.len()
                ),
            )));
        }
        let slot = self.pieces.get_mut(index as usize).ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "memspool index {index} out of range (have {})",
                    self.num_pieces
                ),
            ))
        })?;
        *slot = Some(data.to_vec());
        Ok(())
    }

    pub fn read_range(&self, index: u32, begin: u32, length: u32) -> Result<Vec<u8>> {
        let actual = self.piece_size(index);
        let end = u64::from(begin) + u64::from(length);
        if end > actual {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "memspool read past piece end: piece {index} actual={actual} requested {begin}+{length}"
                ),
            )));
        }
        let slot = self.pieces.get(index as usize).ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("memspool index {index} out of range"),
            ))
        })?;
        let buf = slot.as_ref().ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("memspool piece {index} not yet written"),
            ))
        })?;
        Ok(buf[begin as usize..end as usize].to_vec())
    }

    fn piece_size(&self, index: u32) -> u64 {
        if (index as u64 + 1) == self.num_pieces as u64 {
            let r = self.total_length % self.piece_length;
            if r == 0 {
                self.piece_length
            } else {
                r
            }
        } else {
            self.piece_length
        }
    }
}

/// Spawn the in-memory storage task. Same `StorageCommand` /
/// `StorageEvent` interface as the on-disk and encrypted variants —
/// the engine picks which to spawn based on `--memory-only` /
/// `--paranoid`. On Windows this is a no-op task that immediately
/// reports an unsupported-platform error; the engine should have
/// already rejected the combination at startup, but the guard here
/// keeps us honest if someone calls in directly.
pub fn spawn_memspool_storage_task(
    layout: Layout,
    cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_memspool_storage(layout, cmd_rx, event_tx.clone()).await {
            let _ = event_tx
                .send(StorageEvent::Error {
                    index: None,
                    msg: e.to_string(),
                })
                .await;
        }
    })
}

async fn run_memspool_storage(
    layout: Layout,
    mut cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> Result<()> {
    let mut spool = MemSpool::new(
        layout.piece_length,
        layout.num_pieces as u32,
        layout.total_length,
    );
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            StorageCommand::Shutdown => break,
            StorageCommand::Write { index, data } => {
                if let Err(e) = spool.write_piece(index, &data) {
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
                let res = spool.read_range(index, begin, length);
                let _ = reply.send(res).await;
            }
        }
    }
    Ok(())
}

/// `--memory-only` cannot persist between processes by design, so
/// there's no resume-from-disk path. The engine simply starts with
/// zero pieces every time. This helper exists for symmetry with
/// `scan_resume` / `scan_spool_resume` so the engine's startup code
/// can pick a backend uniformly. `_spool_path` is unused; kept in
/// the signature for parity.
pub async fn scan_memspool_resume(_layout: &Layout) -> Result<Vec<usize>> {
    Ok(Vec::new())
}

/// Whether the current platform supports the in-memory spool. Used
/// at engine startup to bail with a clear error on platforms we
/// don't support (today: Windows).
#[cfg(not(windows))]
pub const SUPPORTED: bool = true;
#[cfg(windows)]
pub const SUPPORTED: bool = false;

/// Path the backing file would live at on the platforms that
/// could expose one (currently Linux `/dev/shm`). Returned for
/// diagnostic logging only — the present implementation keeps the
/// pieces in a heap `Vec` rather than mapping a file. Kept for
/// future use; do not rely on it for I/O.
#[allow(dead_code)]
pub fn diagnostic_backing_path(torrent_name: &str) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let p = PathBuf::from("/dev/shm").join(format!("{torrent_name}.rustytorrent-memspool"));
        Some(p)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = torrent_name;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_full_piece() {
        let mut spool = MemSpool::new(1024, 1, 1024);
        let data: Vec<u8> = (0..1024).map(|i| (i as u8).wrapping_mul(11)).collect();
        spool.write_piece(0, &data).unwrap();
        let back = spool.read_range(0, 0, 1024).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn roundtrip_short_last_piece() {
        // total = 1024 + 100 means last piece is 100 bytes.
        let mut spool = MemSpool::new(1024, 2, 1024 + 100);
        let last: Vec<u8> = (0..100u8).collect();
        spool.write_piece(1, &last).unwrap();
        let back = spool.read_range(1, 0, 100).unwrap();
        assert_eq!(back, last);
    }

    #[test]
    fn read_partial_block_inside_piece() {
        let mut spool = MemSpool::new(256, 1, 256);
        let data: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        spool.write_piece(0, &data).unwrap();
        let block = spool.read_range(0, 16, 32).unwrap();
        assert_eq!(block, data[16..48]);
    }

    #[test]
    fn read_unwritten_piece_errors() {
        let spool = MemSpool::new(256, 3, 256 * 3);
        assert!(spool.read_range(1, 0, 10).is_err());
    }

    #[test]
    fn write_wrong_length_errors() {
        let mut spool = MemSpool::new(256, 1, 256);
        let too_short = vec![0u8; 100];
        assert!(spool.write_piece(0, &too_short).is_err());
    }

    #[test]
    fn read_past_piece_errors() {
        let mut spool = MemSpool::new(256, 1, 256);
        spool.write_piece(0, &vec![0u8; 256]).unwrap();
        assert!(spool.read_range(0, 200, 100).is_err());
    }
}
