//! Torrent creation (BEP 3): turn a file or directory into a `.torrent`.
//!
//! This is the inverse of the parsing in [`crate::metainfo`]. We hash the
//! input in `piece_length` chunks, assemble the `info` dictionary, and
//! bencode it. The info-hash is the SHA-1 of the canonical bencoding of
//! that `info` dict — and because [`crate::metainfo::bencode::BencodeValue::Dict`]
//! is a `BTreeMap`, key order is canonical by construction, so the hash a
//! third party computes from our output matches ours byte-for-byte.
//!
//! Scope: single file, or a directory walked recursively (BEP 3
//! multi-file). Symlinks are not followed — only regular files are
//! hashed, so a malicious symlink in the tree can't pull in content from
//! outside it.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

use crate::error::{Error, Result};
use crate::metainfo::bencode::BencodeValue;

/// Default piece length: 256 KiB. A reasonable middle ground — small
/// enough for fast first-piece verification, large enough to keep the
/// pieces string modest for big payloads.
pub const DEFAULT_PIECE_LENGTH: u64 = 256 * 1024;

/// One input file: its on-disk path plus the path components to record in
/// the torrent (relative to the root dir, for the multi-file case).
struct InputFile {
    disk_path: PathBuf,
    /// Relative components under the torrent name dir. Empty for the
    /// single-file case.
    rel_components: Vec<String>,
    length: u64,
}

/// Build a `.torrent`'s raw bytes from `input` (a file or directory).
///
/// - `trackers`: announce URLs. The first becomes `announce`; all of them
///   go into `announce-list` (BEP 12) when there's more than one.
/// - `piece_length`: bytes per piece; must be > 0.
/// - `name_override`: torrent display name; defaults to the input's file
///   name.
/// - `private`: set the BEP 27 `private` flag (no DHT/PEX for this torrent).
///
/// Returns `(torrent_bytes, info_hash)`.
pub fn create_torrent(
    input: &Path,
    trackers: &[String],
    piece_length: u64,
    name_override: Option<String>,
    private: bool,
) -> Result<(Vec<u8>, [u8; 20])> {
    if piece_length == 0 {
        return Err(Error::Bencode("piece length must be > 0".into()));
    }
    let meta = std::fs::metadata(input)
        .map_err(|e| Error::Bencode(format!("stat {}: {e}", input.display())))?;

    let name = name_override.unwrap_or_else(|| {
        input
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "torrent".to_string())
    });

    let (files, single_file): (Vec<InputFile>, bool) = if meta.is_file() {
        (
            vec![InputFile {
                disk_path: input.to_path_buf(),
                rel_components: Vec::new(),
                length: meta.len(),
            }],
            true,
        )
    } else if meta.is_dir() {
        let mut collected = Vec::new();
        collect_files(input, &mut Vec::new(), &mut collected)?;
        // BEP 3 doesn't mandate ordering, but a deterministic (sorted)
        // order makes the output reproducible across filesystems.
        collected.sort_by(|a, b| a.rel_components.cmp(&b.rel_components));
        if collected.is_empty() {
            return Err(Error::Bencode(format!(
                "directory {} contains no regular files",
                input.display()
            )));
        }
        (collected, false)
    } else {
        return Err(Error::Bencode(format!(
            "{} is neither a regular file nor a directory",
            input.display()
        )));
    };

    // Hash the concatenated stream of all files in order, in
    // piece_length chunks. The final piece may be short.
    let pieces = hash_pieces(&files, piece_length)?;

    // Assemble the info dict.
    let mut info: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
    info.insert(b"name".to_vec(), BencodeValue::Bytes(name.into_bytes()));
    info.insert(
        b"piece length".to_vec(),
        BencodeValue::Int(piece_length as i64),
    );
    info.insert(b"pieces".to_vec(), BencodeValue::Bytes(pieces));
    if private {
        info.insert(b"private".to_vec(), BencodeValue::Int(1));
    }
    if single_file {
        info.insert(
            b"length".to_vec(),
            BencodeValue::Int(files[0].length as i64),
        );
    } else {
        let file_list: Vec<BencodeValue> = files
            .iter()
            .map(|f| {
                let mut d: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
                d.insert(b"length".to_vec(), BencodeValue::Int(f.length as i64));
                d.insert(
                    b"path".to_vec(),
                    BencodeValue::List(
                        f.rel_components
                            .iter()
                            .map(|c| BencodeValue::Bytes(c.clone().into_bytes()))
                            .collect(),
                    ),
                );
                BencodeValue::Dict(d)
            })
            .collect();
        info.insert(b"files".to_vec(), BencodeValue::List(file_list));
    }

    let info_val = BencodeValue::Dict(info);
    let info_bytes = info_val.to_bytes();
    let mut hasher = Sha1::new();
    hasher.update(&info_bytes);
    let info_hash: [u8; 20] = hasher.finalize().into();

    // Top-level dict: info + announce / announce-list.
    let mut top: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
    top.insert(b"info".to_vec(), info_val);
    if let Some(first) = trackers.first() {
        top.insert(
            b"announce".to_vec(),
            BencodeValue::Bytes(first.clone().into_bytes()),
        );
    }
    if trackers.len() > 1 {
        // BEP 12 announce-list: a list of tiers, each a list of URLs. We
        // emit one tier per tracker (simplest valid form).
        let tiers: Vec<BencodeValue> = trackers
            .iter()
            .map(|u| BencodeValue::List(vec![BencodeValue::Bytes(u.clone().into_bytes())]))
            .collect();
        top.insert(b"announce-list".to_vec(), BencodeValue::List(tiers));
    }

    Ok((BencodeValue::Dict(top).to_bytes(), info_hash))
}

/// Recursively collect regular files under `dir`, recording each one's
/// path components relative to the torrent root. Skips symlinks and
/// non-regular entries so the torrent can only describe content that
/// genuinely lives under the input directory.
fn collect_files(dir: &Path, prefix: &mut Vec<String>, out: &mut Vec<InputFile>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::Bencode(format!("read dir {}: {e}", dir.display())))?;
    // Sort entries for deterministic traversal.
    let mut names: Vec<(String, PathBuf, std::fs::FileType)> = Vec::new();
    for e in entries {
        let e = e.map_err(|e| Error::Bencode(format!("dir entry: {e}")))?;
        let ft = e
            .file_type()
            .map_err(|e| Error::Bencode(format!("file type: {e}")))?;
        names.push((e.file_name().to_string_lossy().into_owned(), e.path(), ft));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path, ft) in names {
        if ft.is_symlink() {
            // Don't follow symlinks — avoid escaping the input tree.
            continue;
        }
        if ft.is_dir() {
            prefix.push(name);
            collect_files(&path, prefix, out)?;
            prefix.pop();
        } else if ft.is_file() {
            let len = std::fs::metadata(&path)
                .map_err(|e| Error::Bencode(format!("stat {}: {e}", path.display())))?
                .len();
            let mut rel = prefix.clone();
            rel.push(name);
            out.push(InputFile {
                disk_path: path,
                rel_components: rel,
                length: len,
            });
        }
        // Other types (sockets, devices) are silently skipped.
    }
    Ok(())
}

/// Stream every file in order and SHA-1 each `piece_length` chunk of the
/// concatenated byte stream. Returns the concatenated 20-byte hashes.
fn hash_pieces(files: &[InputFile], piece_length: u64) -> Result<Vec<u8>> {
    let mut pieces = Vec::new();
    let mut buf = vec![0u8; piece_length as usize];
    let mut filled = 0usize; // bytes currently in `buf`

    for f in files {
        let mut file = std::fs::File::open(&f.disk_path)
            .map_err(|e| Error::Bencode(format!("open {}: {e}", f.disk_path.display())))?;
        loop {
            // Fill the rest of the current piece buffer.
            let n = file
                .read(&mut buf[filled..])
                .map_err(|e| Error::Bencode(format!("read {}: {e}", f.disk_path.display())))?;
            if n == 0 {
                break; // EOF for this file
            }
            filled += n;
            if filled == buf.len() {
                let mut h = Sha1::new();
                h.update(&buf);
                pieces.extend_from_slice(&h.finalize());
                filled = 0;
            }
        }
    }
    // Final short piece, if any bytes remain.
    if filled > 0 {
        let mut h = Sha1::new();
        h.update(&buf[..filled]);
        pieces.extend_from_slice(&h.finalize());
    }
    Ok(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::TorrentFile;

    fn scratch() -> PathBuf {
        // A process-wide counter guarantees a distinct dir per call even when
        // two parallel test threads read an identical `now()` (coarse clock
        // resolution made `pid+nanos` alone collide, so colliding tests raced
        // each other's writes / remove_dir_all — an intermittent failure).
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "rt_create_{}_{}_{}",
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

    #[test]
    fn single_file_roundtrips_through_parser() {
        let dir = scratch();
        let file = dir.join("hello.bin");
        // 1.5 pieces at 1024 piece length → 2 pieces, last one short.
        std::fs::write(&file, vec![0xABu8; 1536]).unwrap();

        let (bytes, info_hash) = create_torrent(
            &file,
            &["http://t.example/announce".into()],
            1024,
            None,
            false,
        )
        .unwrap();

        // Our own parser must accept it and recompute the same info-hash.
        let t = TorrentFile::from_bytes(&bytes).unwrap();
        assert_eq!(t.info_hash, info_hash);
        assert_eq!(t.info.name, "hello.bin");
        assert_eq!(t.info.piece_length, 1024);
        assert_eq!(t.info.piece_hashes.len(), 2);
        assert_eq!(t.total_length(), 1536);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn multi_file_directory_lists_files_sorted() {
        let dir = scratch();
        let root = dir.join("payload");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("b.txt"), b"bbbb").unwrap();
        std::fs::write(root.join("a.txt"), b"aaaaaa").unwrap();
        std::fs::write(root.join("sub/c.txt"), b"cc").unwrap();

        let (bytes, info_hash) = create_torrent(&root, &[], 4, None, false).unwrap();
        let t = TorrentFile::from_bytes(&bytes).unwrap();
        assert_eq!(t.info_hash, info_hash);
        assert_eq!(t.info.name, "payload");
        // 4 + 6 + 2 = 12 bytes total.
        assert_eq!(t.total_length(), 12);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn private_flag_is_set() {
        let dir = scratch();
        let file = dir.join("p.bin");
        std::fs::write(&file, b"data").unwrap();
        let (bytes, _) = create_torrent(&file, &[], 1024, Some("custom".into()), true).unwrap();
        let t = TorrentFile::from_bytes(&bytes).unwrap();
        assert!(t.info.private);
        assert_eq!(t.info.name, "custom");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_zero_piece_length() {
        let dir = scratch();
        let file = dir.join("z.bin");
        std::fs::write(&file, b"x").unwrap();
        assert!(create_torrent(&file, &[], 0, None, false).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
