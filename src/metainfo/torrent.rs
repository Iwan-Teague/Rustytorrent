use std::path::PathBuf;

use sha1::{Digest, Sha1};

use crate::error::{Error, Result};
use crate::metainfo::bencode::{skip_value, BencodeValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentFile {
    pub info_hash: [u8; 20],
    pub announce: Option<String>,
    pub announce_list: Vec<Vec<String>>,
    pub info: Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub name: String,
    pub piece_length: u64,
    pub piece_hashes: Vec<[u8; 20]>,
    pub files: TorrentFiles,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorrentFiles {
    Single { length: u64 },
    Multi { files: Vec<FileEntry> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub length: u64,
    pub path: PathBuf,
}

impl TorrentFile {
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let root = BencodeValue::parse_all(input)?;
        let info_hash = compute_info_hash(input)?;
        Self::from_value(root, info_hash)
    }

    fn from_value(root: BencodeValue, info_hash: [u8; 20]) -> Result<Self> {
        let dict = root.as_dict()?;

        let announce = dict
            .get(&b"announce".to_vec())
            .map(|v| v.as_str().map(|s| s.to_string()))
            .transpose()?;

        let announce_list = match dict.get(&b"announce-list".to_vec()) {
            None => Vec::new(),
            Some(v) => {
                let tiers = v.as_list()?;
                let mut out = Vec::with_capacity(tiers.len());
                for tier in tiers {
                    let urls = tier.as_list()?;
                    let mut row = Vec::with_capacity(urls.len());
                    for u in urls {
                        row.push(u.as_str()?.to_string());
                    }
                    out.push(row);
                }
                out
            }
        };

        let info_v = dict
            .get(&b"info".to_vec())
            .ok_or_else(|| Error::Bencode("missing info dict".into()))?;
        let info = Info::from_value(info_v)?;

        Ok(TorrentFile {
            info_hash,
            announce,
            announce_list,
            info,
        })
    }

    pub fn total_length(&self) -> u64 {
        match &self.info.files {
            TorrentFiles::Single { length } => *length,
            TorrentFiles::Multi { files } => files.iter().map(|f| f.length).sum(),
        }
    }

    pub fn num_pieces(&self) -> usize {
        self.info.piece_hashes.len()
    }

    pub fn trackers(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for tier in &self.announce_list {
            for url in tier {
                if !out.contains(url) {
                    out.push(url.clone());
                }
            }
        }
        if let Some(a) = &self.announce {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
        out
    }
}

impl Info {
    fn from_value(v: &BencodeValue) -> Result<Self> {
        let d = v.as_dict()?;
        let name = d
            .get(&b"name".to_vec())
            .ok_or_else(|| Error::Bencode("info missing name".into()))?
            .as_str()?
            .to_string();
        let piece_length = u64::try_from(
            d.get(&b"piece length".to_vec())
                .ok_or_else(|| Error::Bencode("info missing piece length".into()))?
                .as_int()?,
        )
        .map_err(|_| Error::Bencode("piece length negative".into()))?;
        let pieces_raw = d
            .get(&b"pieces".to_vec())
            .ok_or_else(|| Error::Bencode("info missing pieces".into()))?
            .as_bytes()?;
        if !pieces_raw.len().is_multiple_of(20) {
            return Err(Error::Bencode(format!(
                "pieces length {} not multiple of 20",
                pieces_raw.len()
            )));
        }
        let piece_hashes: Vec<[u8; 20]> = pieces_raw
            .chunks_exact(20)
            .map(|c| {
                let mut h = [0u8; 20];
                h.copy_from_slice(c);
                h
            })
            .collect();

        let private = d
            .get(&b"private".to_vec())
            .and_then(|v| v.as_int().ok())
            .map(|n| n != 0)
            .unwrap_or(false);

        let files = if let Some(files_v) = d.get(&b"files".to_vec()) {
            let list = files_v.as_list()?;
            let mut entries = Vec::with_capacity(list.len());
            for fv in list {
                let fd = fv.as_dict()?;
                let length = u64::try_from(
                    fd.get(&b"length".to_vec())
                        .ok_or_else(|| Error::Bencode("file missing length".into()))?
                        .as_int()?,
                )
                .map_err(|_| Error::Bencode("file length negative".into()))?;
                let path_list = fd
                    .get(&b"path".to_vec())
                    .ok_or_else(|| Error::Bencode("file missing path".into()))?
                    .as_list()?;
                let mut p = PathBuf::new();
                for seg in path_list {
                    let s = seg.as_str()?;
                    if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\\')
                    {
                        return Err(Error::Bencode(format!("unsafe path segment: {s}")));
                    }
                    p.push(s);
                }
                entries.push(FileEntry { length, path: p });
            }
            TorrentFiles::Multi { files: entries }
        } else {
            let length = u64::try_from(
                d.get(&b"length".to_vec())
                    .ok_or_else(|| Error::Bencode("info missing length".into()))?
                    .as_int()?,
            )
            .map_err(|_| Error::Bencode("length negative".into()))?;
            TorrentFiles::Single { length }
        };

        Ok(Info {
            name,
            piece_length,
            piece_hashes,
            files,
            private,
        })
    }
}

/// Compute SHA1 of the raw bencoded `info` dictionary bytes from the original input.
/// We walk the top-level dict keys manually so we capture the exact byte slice that
/// the original encoder produced — re-encoding would risk a hash mismatch.
fn compute_info_hash(input: &[u8]) -> Result<[u8; 20]> {
    let info_slice = find_info_slice(input)?;
    let mut hasher = Sha1::new();
    hasher.update(info_slice);
    Ok(hasher.finalize().into())
}

fn find_info_slice(input: &[u8]) -> Result<&[u8]> {
    if input.first() != Some(&b'd') {
        return Err(Error::Bencode("torrent root is not a dict".into()));
    }
    let mut cursor = 1usize;
    while cursor < input.len() {
        if input[cursor] == b'e' {
            return Err(Error::Bencode("no info dict in root".into()));
        }
        let key_start = cursor;
        let key_len = skip_value(&input[cursor..])?;
        cursor += key_len;
        let key = parse_bytes_inline(&input[key_start..key_start + key_len])?;
        let value_start = cursor;
        let value_len = skip_value(&input[cursor..])?;
        cursor += value_len;
        if key == b"info" {
            return Ok(&input[value_start..value_start + value_len]);
        }
    }
    Err(Error::Bencode("malformed top-level dict".into()))
}

fn parse_bytes_inline(input: &[u8]) -> Result<Vec<u8>> {
    let (v, rest) = BencodeValue::parse(input)?;
    if !rest.is_empty() {
        return Err(Error::Bencode("trailing bytes after key".into()));
    }
    match v {
        BencodeValue::Bytes(b) => Ok(b),
        _ => Err(Error::Bencode("dict key is not bytes".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid single-file torrent.
    fn build_single_file_torrent() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"d");
        out.extend_from_slice(b"8:announce");
        out.extend_from_slice(b"21:http://tracker.test/a");
        out.extend_from_slice(b"4:info");
        out.extend_from_slice(b"d");
        out.extend_from_slice(b"6:lengthi12345e");
        out.extend_from_slice(b"4:name8:test.bin");
        out.extend_from_slice(b"12:piece lengthi16384e");
        out.extend_from_slice(b"6:pieces20:");
        out.extend_from_slice(&[0xAAu8; 20]);
        out.extend_from_slice(b"e");
        out.extend_from_slice(b"e");
        out
    }

    fn build_multi_file_torrent() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"d");
        out.extend_from_slice(b"8:announce");
        out.extend_from_slice(b"21:http://tracker.test/a");
        out.extend_from_slice(b"13:announce-list");
        out.extend_from_slice(b"ll21:http://tracker.test/ael21:udp://tracker.test:80ee");
        out.extend_from_slice(b"4:info");
        out.extend_from_slice(b"d");
        out.extend_from_slice(
            b"5:filesld6:lengthi100e4:pathl1:a5:b.txteed6:lengthi200e4:pathl1:c5:d.txteee",
        );
        out.extend_from_slice(b"4:name3:pkg");
        out.extend_from_slice(b"12:piece lengthi32768e");
        out.extend_from_slice(b"6:pieces20:");
        out.extend_from_slice(&[0xBBu8; 20]);
        out.extend_from_slice(b"e");
        out.extend_from_slice(b"e");
        out
    }

    #[test]
    fn parse_single_file() {
        let buf = build_single_file_torrent();
        let t = TorrentFile::from_bytes(&buf).unwrap();
        assert_eq!(t.announce.as_deref(), Some("http://tracker.test/a"));
        assert_eq!(t.info.name, "test.bin");
        assert_eq!(t.info.piece_length, 16384);
        assert_eq!(t.info.piece_hashes.len(), 1);
        assert_eq!(t.total_length(), 12345);
        match t.info.files {
            TorrentFiles::Single { length } => assert_eq!(length, 12345),
            _ => panic!("expected single file"),
        }
    }

    #[test]
    fn parse_multi_file() {
        let buf = build_multi_file_torrent();
        let t = TorrentFile::from_bytes(&buf).unwrap();
        assert_eq!(t.info.name, "pkg");
        assert_eq!(t.info.piece_length, 32768);
        assert_eq!(t.total_length(), 300);
        assert_eq!(t.announce_list.len(), 2);
        match &t.info.files {
            TorrentFiles::Multi { files } => {
                assert_eq!(files.len(), 2);
                assert_eq!(files[0].length, 100);
                assert_eq!(files[0].path, PathBuf::from("a/b.txt"));
                assert_eq!(files[1].length, 200);
                assert_eq!(files[1].path, PathBuf::from("c/d.txt"));
            }
            _ => panic!("expected multi file"),
        }
    }

    #[test]
    fn info_hash_matches_external_sha1() {
        // Known bencode: d4:infod3:keyi42eee  → SHA1 of "d3:keyi42ee"
        let raw = b"d4:infod3:keyi42eeee";
        let _ = TorrentFile::from_bytes(raw); // parse may fail (no torrent fields) but hash extraction tested separately
        let info_slice = find_info_slice(raw).unwrap();
        assert_eq!(info_slice, b"d3:keyi42ee");
        let mut h = Sha1::new();
        h.update(info_slice);
        let digest: [u8; 20] = h.finalize().into();
        // Pre-computed via openssl:
        //   printf 'd3:keyi42ee' | openssl dgst -sha1
        // = 16cc65249f4b64dd61e701205c60870018fb067f
        let expected: [u8; 20] = [
            0x16, 0xcc, 0x65, 0x24, 0x9f, 0x4b, 0x64, 0xdd, 0x61, 0xe7, 0x01, 0x20, 0x5c, 0x60,
            0x87, 0x00, 0x18, 0xfb, 0x06, 0x7f,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn rejects_path_traversal() {
        let mut out = Vec::new();
        out.extend_from_slice(
            b"d4:infod5:filesld6:lengthi1e4:pathl2:..eee4:name1:x12:piece lengthi1e6:pieces20:",
        );
        out.extend_from_slice(&[0u8; 20]);
        out.extend_from_slice(b"eee");
        assert!(TorrentFile::from_bytes(&out).is_err());
    }
}
