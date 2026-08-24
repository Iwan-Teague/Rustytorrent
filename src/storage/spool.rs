//! Encrypted on-disk spool — the B1 `--paranoid` storage backend.
//!
//! Threat: even when every network bit is anonymous, the in-progress
//! files on disk are the smoking gun in a seized-laptop scenario. This
//! module replaces the regular file layout with a single encrypted spool
//! file: every piece is AES-256-GCM-encrypted under a key derived from
//! the user's passphrase via Argon2id. Plaintext is *never* written to
//! disk for the lifetime of the download.
//!
//! On completion the user runs the `decrypt` subcommand with the same
//! passphrase to extract the spool into the real file layout (or just
//! deletes the spool to leave nothing recoverable).
//!
//! ## On-disk layout
//!
//! ```text
//! offset  bytes  meaning
//!   0     4      magic            "RTSP"
//!   4     1      version          1
//!   5     3      reserved         zero
//!   8    16      salt             random per spool, fed back to Argon2id
//!  24     4      num_pieces (LE)  sanity check vs torrent
//!  28     4      piece_length (LE) sanity check vs torrent
//!  32    12      verifier_nonce   for the wrong-passphrase detector
//!  44    32      verifier_ct      AES-GCM(zeros) — decrypt to verify key
//!  76    --      slot 0 starts here
//! ```
//!
//! Per piece slot (size = `piece_length + 28`):
//! ```text
//!   0     12     nonce (random, fresh per write)
//!  12     ?      ciphertext + 16-byte GCM tag
//! ```
//!
//! Every piece is padded with zeros to `piece_length` before encryption
//! so all slots are uniform — the layout doesn't need a per-slot length
//! field. The caller knows the true piece length from the torrent and
//! slices the decrypted plaintext accordingly.
//!
//! Slot-zero specifically is never special-cased; the verifier in the
//! header lets us reject a wrong passphrase even before any slot is
//! populated.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::storage::crypt::{self, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::storage::disk::{StorageCommand, StorageEvent};
use crate::storage::layout::Layout;

pub const MAGIC: &[u8; 4] = b"RTSP";
pub const VERSION: u8 = 1;

/// Open options for the spool file: created owner-only (0600 on Unix).
///
/// The payload is encrypted, but file size still leaks download volume and
/// the header holds the salt/verifier; there is no reason for other local
/// users to read it. `mode` applies only at creation, so an existing spool
/// keeps its permissions.
fn private_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts
}

/// Byte length of the spool header. See module docs for the layout.
pub const HEADER_LEN: u64 =
    4 + 1 + 3 + SALT_LEN as u64 + 4 + 4 + NONCE_LEN as u64 + (16 + TAG_LEN) as u64;

/// 16 zero bytes encrypted at spool creation and stored in the header.
/// On open we attempt to decrypt this with the just-derived key; success
/// means the passphrase is right, failure means stop before we corrupt
/// existing slots by writing under the wrong key.
const VERIFIER_PLAINTEXT: [u8; 16] = [0u8; 16];

/// Per-piece slot size in the encrypted spool.
#[inline]
pub fn slot_size(piece_length: u64) -> u64 {
    NONCE_LEN as u64 + piece_length + TAG_LEN as u64
}

#[inline]
fn slot_offset(piece_length: u64, index: u32) -> u64 {
    HEADER_LEN + (index as u64) * slot_size(piece_length)
}

/// Owns the spool file handle plus the derived key. Methods are async
/// because the file I/O is.
pub struct EncryptedSpool {
    file: File,
    key: [u8; KEY_LEN],
    piece_length: u64,
    num_pieces: u32,
    total_length: u64,
    /// Reused padding buffer for `write_piece`, so the common
    /// download-path write doesn't allocate a fresh full-piece `Vec` every
    /// call. Sized to `piece_length` lazily on first write.
    write_scratch: Vec<u8>,
}

impl EncryptedSpool {
    /// Open the spool at `path`, creating it if absent. On create, write
    /// a fresh header with a random salt and a verifier encrypted under
    /// the just-derived key. On open, validate the magic/version, derive
    /// the key from `passphrase` + the stored salt, and verify it
    /// against the header verifier — wrong passphrase fails closed here
    /// rather than later by silently corrupting slots.
    pub async fn open_or_create(
        path: &Path,
        passphrase: &str,
        piece_length: u64,
        num_pieces: u32,
        total_length: u64,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = private_open_options().open(path).await?;
        let existing_len = file.metadata().await?.len();
        let key = if existing_len == 0 {
            // Fresh spool: write the header now.
            let salt = crypt::random_salt();
            let key = crypt::derive_key(passphrase, &salt)?;
            let (verifier_nonce, verifier_ct) = crypt::encrypt(&key, &VERIFIER_PLAINTEXT)?;
            write_header(
                &mut file,
                &salt,
                num_pieces,
                piece_length as u32,
                &verifier_nonce,
                &verifier_ct,
            )
            .await?;
            // Pre-allocate the full spool so writes are in-place.
            let total_size = HEADER_LEN + (num_pieces as u64) * slot_size(piece_length);
            file.set_len(total_size).await?;
            key
        } else {
            // Existing spool: parse the header, validate, derive, verify.
            let (salt, stored_pieces, stored_piece_len, verifier_nonce, verifier_ct) =
                read_header(&mut file).await?;
            if stored_pieces != num_pieces {
                return Err(Error::Crypto(format!(
                    "spool num_pieces mismatch: file says {stored_pieces}, torrent says {num_pieces}"
                )));
            }
            if u64::from(stored_piece_len) != piece_length {
                return Err(Error::Crypto(format!(
                    "spool piece_length mismatch: file says {stored_piece_len}, torrent says {piece_length}"
                )));
            }
            let key = crypt::derive_key(passphrase, &salt)?;
            // Verifier: decrypting must yield the all-zero plaintext.
            // Any failure here means wrong passphrase or tampered header.
            let decrypted = crypt::decrypt(&key, &verifier_nonce, &verifier_ct).map_err(|_| {
                Error::Crypto(
                    "spool header verifier failed — wrong passphrase or tampered file".into(),
                )
            })?;
            if decrypted != VERIFIER_PLAINTEXT {
                return Err(Error::Crypto(
                    "spool header verifier decrypted but to unexpected bytes".into(),
                ));
            }
            key
        };
        Ok(Self {
            file,
            key,
            piece_length,
            num_pieces,
            total_length,
            write_scratch: Vec::new(),
        })
    }

    /// Encrypt `data` and write it into the slot for `index`. `data`
    /// must be exactly the actual size of that piece (= `piece_length`
    /// for every piece except possibly the last). The plaintext is
    /// zero-padded up to `piece_length` before encryption so all slots
    /// are uniform on disk.
    pub async fn write_piece(&mut self, index: u32, data: &[u8]) -> Result<()> {
        let actual = self.piece_size(index);
        if data.len() as u64 != actual {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "spool write piece {index}: got {} bytes, expected {actual}",
                    data.len()
                ),
            )));
        }
        // Pad up to piece_length so every slot has the same on-disk size.
        // Reuse the scratch buffer to avoid a per-write allocation.
        let buf = &mut self.write_scratch;
        buf.clear();
        buf.extend_from_slice(data);
        buf.resize(self.piece_length as usize, 0);
        let (nonce, ct) = crypt::encrypt(&self.key, buf)?;
        debug_assert_eq!(ct.len() as u64, self.piece_length + TAG_LEN as u64);

        let offset = slot_offset(self.piece_length, index);
        self.file.seek(SeekFrom::Start(offset)).await?;
        self.file.write_all(&nonce).await?;
        self.file.write_all(&ct).await?;
        // Flush per-piece — same durability discipline as the plain disk
        // task. A crash mid-piece loses that one piece; the rest survives.
        self.file.flush().await?;
        Ok(())
    }

    /// Read the slot for `index`, decrypt it, and return the requested
    /// `[begin .. begin+length]` slice of the actual piece. Reads of an
    /// unwritten slot return a decryption error (the slot's still
    /// zero-filled, which won't authenticate under any key).
    pub async fn read_range(&mut self, index: u32, begin: u32, length: u32) -> Result<Vec<u8>> {
        let actual = self.piece_size(index);
        let end = u64::from(begin) + u64::from(length);
        if end > actual {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "spool read past piece end: piece {index} actual={actual} requested {begin}+{length}"
                ),
            )));
        }
        let offset = slot_offset(self.piece_length, index);
        self.file.seek(SeekFrom::Start(offset)).await?;
        let mut nonce_buf = [0u8; NONCE_LEN];
        self.file.read_exact(&mut nonce_buf).await?;
        let ct_len = (self.piece_length + TAG_LEN as u64) as usize;
        let mut ct = vec![0u8; ct_len];
        self.file.read_exact(&mut ct).await?;
        let mut plaintext = crypt::decrypt(&self.key, &nonce_buf, &ct)?;
        // Strip the padding back down to the actual piece size before
        // slicing — pieces beyond the last are zero-padded on encrypt.
        plaintext.truncate(actual as usize);
        let begin = begin as usize;
        let end = end as usize;
        // Fast path: a full-piece read (the upload cache's pattern) can
        // hand back the decrypted buffer directly instead of cloning a
        // sub-slice out of it.
        if begin == 0 && end == plaintext.len() {
            return Ok(plaintext);
        }
        Ok(plaintext[begin..end].to_vec())
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

async fn write_header(
    file: &mut File,
    salt: &[u8; SALT_LEN],
    num_pieces: u32,
    piece_length: u32,
    verifier_nonce: &[u8; NONCE_LEN],
    verifier_ct: &[u8],
) -> Result<()> {
    debug_assert_eq!(verifier_ct.len(), VERIFIER_PLAINTEXT.len() + TAG_LEN);
    file.seek(SeekFrom::Start(0)).await?;
    file.write_all(MAGIC).await?;
    file.write_all(&[VERSION]).await?;
    file.write_all(&[0u8, 0u8, 0u8]).await?; // reserved
    file.write_all(salt).await?;
    file.write_all(&num_pieces.to_le_bytes()).await?;
    file.write_all(&piece_length.to_le_bytes()).await?;
    file.write_all(verifier_nonce).await?;
    file.write_all(verifier_ct).await?;
    file.flush().await?;
    Ok(())
}

#[allow(clippy::type_complexity)]
async fn read_header(
    file: &mut File,
) -> Result<(
    [u8; SALT_LEN],
    u32, // num_pieces
    u32, // piece_length
    [u8; NONCE_LEN],
    Vec<u8>, // verifier_ct
)> {
    file.seek(SeekFrom::Start(0)).await?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        return Err(Error::Crypto(format!(
            "spool magic mismatch: got {magic:?}, expected RTSP"
        )));
    }
    let mut version = [0u8; 1];
    file.read_exact(&mut version).await?;
    if version[0] != VERSION {
        return Err(Error::Crypto(format!(
            "spool version mismatch: got {}, expected {VERSION}",
            version[0]
        )));
    }
    let mut reserved = [0u8; 3];
    file.read_exact(&mut reserved).await?;
    let mut salt = [0u8; SALT_LEN];
    file.read_exact(&mut salt).await?;
    let mut np_bytes = [0u8; 4];
    file.read_exact(&mut np_bytes).await?;
    let num_pieces = u32::from_le_bytes(np_bytes);
    let mut pl_bytes = [0u8; 4];
    file.read_exact(&mut pl_bytes).await?;
    let piece_length = u32::from_le_bytes(pl_bytes);
    let mut verifier_nonce = [0u8; NONCE_LEN];
    file.read_exact(&mut verifier_nonce).await?;
    let mut verifier_ct = vec![0u8; VERIFIER_PLAINTEXT.len() + TAG_LEN];
    file.read_exact(&mut verifier_ct).await?;
    Ok((salt, num_pieces, piece_length, verifier_nonce, verifier_ct))
}

/// Spawn the encrypted-spool storage task. Same `StorageCommand`/
/// `StorageEvent` interface as the plain disk task — the engine picks
/// which one to spawn based on `--paranoid`.
pub fn spawn_encrypted_storage_task(
    spool_path: PathBuf,
    passphrase: String,
    layout: Layout,
    cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) =
            run_encrypted_storage(spool_path, passphrase, layout, cmd_rx, event_tx.clone()).await
        {
            let _ = event_tx
                .send(StorageEvent::Error {
                    index: None,
                    msg: e.to_string(),
                })
                .await;
        }
    })
}

async fn run_encrypted_storage(
    spool_path: PathBuf,
    passphrase: String,
    layout: Layout,
    mut cmd_rx: mpsc::Receiver<StorageCommand>,
    event_tx: mpsc::Sender<StorageEvent>,
) -> Result<()> {
    let mut spool = EncryptedSpool::open_or_create(
        &spool_path,
        &passphrase,
        layout.piece_length,
        layout.num_pieces as u32,
        layout.total_length,
    )
    .await?;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            StorageCommand::Shutdown => break,
            StorageCommand::Write { index, data } => {
                if let Err(e) = spool.write_piece(index, &data).await {
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
                let res = spool.read_range(index, begin, length).await;
                let _ = reply.send(res).await;
            }
        }
    }
    Ok(())
}

/// Resume scan for paranoid mode. Walks the spool slot-by-slot,
/// attempting to decrypt + hash-verify each piece against the torrent's
/// expected hashes; returns the set of slot indices that decrypt
/// cleanly AND match the expected hash. Slots that won't decrypt
/// (unwritten, or stored under a different passphrase) are treated as
/// "not yet present" — the engine will simply re-fetch them.
///
/// If the spool file doesn't exist yet, returns an empty set without
/// creating one. Spool creation only happens inside the storage task.
pub async fn scan_spool_resume(
    spool_path: &Path,
    passphrase: &str,
    layout: &Layout,
    piece_hashes: &[[u8; 20]],
) -> Result<Vec<usize>> {
    if !tokio::fs::try_exists(spool_path).await.unwrap_or(false) {
        return Ok(Vec::new());
    }
    let mut spool = EncryptedSpool::open_or_create(
        spool_path,
        passphrase,
        layout.piece_length,
        layout.num_pieces as u32,
        layout.total_length,
    )
    .await?;
    let mut out = Vec::new();
    for index in 0..(layout.num_pieces as u32) {
        let actual = spool.piece_size(index);
        if let Ok(piece) = spool.read_range(index, 0, actual as u32).await {
            if (index as usize) < piece_hashes.len()
                && crate::piece::verify_piece(&piece, &piece_hashes[index as usize])
            {
                out.push(index as usize);
            }
        }
    }
    Ok(out)
}

/// Read every populated slot in the spool, decrypt, hash-verify against
/// the torrent's piece hashes, and emit `(index, plaintext)` pairs to
/// the caller's channel. Used by the `decrypt` subcommand to extract
/// finished pieces into the real file layout. Slots that fail to
/// authenticate are skipped (treated as "not yet written").
pub async fn decrypt_all_pieces(
    spool_path: &Path,
    passphrase: &str,
    layout: &Layout,
    piece_hashes: &[[u8; 20]],
) -> Result<Vec<(u32, Vec<u8>)>> {
    // Guard: unlike the storage task (which legitimately creates the spool on
    // first run), `decrypt` is a read-only extraction command. If the path
    // doesn't exist the user almost certainly gave a wrong path; silently
    // creating an empty spool here would yield "Recovered 0 pieces" with no
    // useful signal. Fail loudly instead, mirroring scan_spool_resume.
    if !tokio::fs::try_exists(spool_path).await.unwrap_or(false) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("spool not found at {}", spool_path.display()),
        )));
    }
    let mut spool = EncryptedSpool::open_or_create(
        spool_path,
        passphrase,
        layout.piece_length,
        layout.num_pieces as u32,
        layout.total_length,
    )
    .await?;
    let mut out = Vec::new();
    for index in 0..(layout.num_pieces as u32) {
        let actual = spool.piece_size(index);
        match spool.read_range(index, 0, actual as u32).await {
            Ok(piece_bytes) => {
                if (index as usize) < piece_hashes.len()
                    && crate::piece::verify_piece(&piece_bytes, &piece_hashes[index as usize])
                {
                    out.push((index, piece_bytes));
                }
                // Otherwise: decrypted but bad hash — treat as not-yet-complete and skip.
            }
            Err(_) => {
                // Slot is empty / unauthenticated — piece simply isn't
                // present yet in the spool. Skip without raising; the
                // user can resume to fill it.
                continue;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        // A process-wide counter guarantees a distinct dir per call. The five
        // tests here shared a nanos-only name, so two parallel threads reading
        // an identical `now()` (coarse clock resolution) would collide and race
        // each other's spool files. pid + counter make every call unique.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustytorrent-spool-test-{}-{}-{}",
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

    #[cfg(unix)]
    #[tokio::test]
    async fn created_spool_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let path = dir.join("spool.bin");
        let _spool = EncryptedSpool::open_or_create(&path, "pw", 1024, 1, 1024)
            .await
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(format!("{mode:o}"), "600", "spool must be owner-only");
    }

    #[tokio::test]
    async fn roundtrip_one_full_piece() {
        let dir = tempdir();
        let path = dir.join("spool.bin");
        let piece_length = 1024u64;
        let num_pieces = 1u32;
        let total = piece_length;
        let mut spool =
            EncryptedSpool::open_or_create(&path, "hunter2", piece_length, num_pieces, total)
                .await
                .unwrap();
        let data: Vec<u8> = (0..1024).map(|i| (i as u8).wrapping_mul(7)).collect();
        spool.write_piece(0, &data).await.unwrap();
        let back = spool.read_range(0, 0, data.len() as u32).await.unwrap();
        assert_eq!(back, data);
    }

    #[tokio::test]
    async fn roundtrip_short_last_piece() {
        // Total length less than piece_length × num_pieces — last piece is
        // short. Slot still occupies a full piece_length on disk.
        let dir = tempdir();
        let path = dir.join("spool.bin");
        let piece_length = 1024u64;
        let num_pieces = 2u32;
        let total = piece_length + 100; // piece 1 is 100 bytes
        let mut spool = EncryptedSpool::open_or_create(&path, "k", piece_length, num_pieces, total)
            .await
            .unwrap();
        let last: Vec<u8> = (0..100u8).collect();
        spool.write_piece(1, &last).await.unwrap();
        let back = spool.read_range(1, 0, 100).await.unwrap();
        assert_eq!(back, last);
    }

    #[tokio::test]
    async fn wrong_passphrase_fails_open() {
        let dir = tempdir();
        let path = dir.join("spool.bin");
        let pl = 256u64;
        let np = 1u32;
        let total = pl;
        {
            let mut spool = EncryptedSpool::open_or_create(&path, "right", pl, np, total)
                .await
                .unwrap();
            spool.write_piece(0, &vec![9u8; pl as usize]).await.unwrap();
        }
        // Reopen with wrong passphrase — must fail at open (verifier check),
        // not later by silently corrupting slot 0.
        let res = EncryptedSpool::open_or_create(&path, "wrong", pl, np, total).await;
        assert!(res.is_err(), "wrong passphrase should be rejected at open");
    }

    #[tokio::test]
    async fn read_unwritten_slot_is_an_error() {
        let dir = tempdir();
        let path = dir.join("spool.bin");
        let pl = 256u64;
        let mut spool = EncryptedSpool::open_or_create(&path, "k", pl, 3, pl * 3)
            .await
            .unwrap();
        // Never write slot 1 — read should fail decryption.
        assert!(spool.read_range(1, 0, 10).await.is_err());
    }

    #[tokio::test]
    async fn second_open_with_same_passphrase_keeps_existing_pieces() {
        let dir = tempdir();
        let path = dir.join("spool.bin");
        let pl = 512u64;
        let np = 2u32;
        let total = pl * 2;
        let data: Vec<u8> = (0..512).map(|i| (i as u8).wrapping_add(3)).collect();
        {
            let mut spool = EncryptedSpool::open_or_create(&path, "kw", pl, np, total)
                .await
                .unwrap();
            spool.write_piece(0, &data).await.unwrap();
        }
        // Re-open — slot 0 should still decrypt cleanly.
        let mut spool = EncryptedSpool::open_or_create(&path, "kw", pl, np, total)
            .await
            .unwrap();
        let back = spool.read_range(0, 0, data.len() as u32).await.unwrap();
        assert_eq!(back, data);
    }
}
