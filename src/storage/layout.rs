use std::path::PathBuf;

use crate::metainfo::{TorrentFile, TorrentFiles};

/// One physical file in a multi-file torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpan {
    pub path: PathBuf,
    /// Byte offset within the concatenated torrent stream where this file starts.
    pub start: u64,
    /// File length in bytes.
    pub length: u64,
}

impl FileSpan {
    pub fn end(&self) -> u64 {
        self.start + self.length
    }
}

/// Maps logical byte positions in a torrent stream to physical file regions.
/// One piece may span multiple files, so a single write becomes multiple slices.
#[derive(Debug, Clone)]
pub struct Layout {
    pub root: PathBuf,
    pub files: Vec<FileSpan>,
    pub piece_length: u64,
    pub total_length: u64,
    pub num_pieces: usize,
}

impl Layout {
    pub fn from_torrent(root: PathBuf, t: &TorrentFile) -> Self {
        let mut files: Vec<FileSpan> = Vec::new();
        let mut offset: u64 = 0;
        match &t.info.files {
            TorrentFiles::Single { length } => {
                files.push(FileSpan {
                    path: root.join(&t.info.name),
                    start: 0,
                    length: *length,
                });
            }
            TorrentFiles::Multi { files: entries } => {
                for e in entries {
                    let full = root.join(&t.info.name).join(&e.path);
                    files.push(FileSpan {
                        path: full,
                        start: offset,
                        length: e.length,
                    });
                    offset += e.length;
                }
            }
        }
        Layout {
            root,
            files,
            piece_length: t.info.piece_length,
            total_length: t.total_length(),
            num_pieces: t.num_pieces(),
        }
    }

    /// Map a global byte range `[start, start + length)` to (file index, file offset, count) tuples.
    pub fn slices(&self, global_start: u64, length: u64) -> Vec<(usize, u64, u64)> {
        let end = global_start + length;
        let mut out = Vec::new();
        for (i, f) in self.files.iter().enumerate() {
            if f.end() <= global_start {
                continue;
            }
            if f.start >= end {
                break;
            }
            let slice_start = global_start.max(f.start);
            let slice_end = end.min(f.end());
            if slice_end <= slice_start {
                continue;
            }
            let file_off = slice_start - f.start;
            out.push((i, file_off, slice_end - slice_start));
        }
        out
    }

    /// Convenience: map a piece index to file slices.
    pub fn slices_for_piece(&self, piece_index: usize, piece_size: u64) -> Vec<(usize, u64, u64)> {
        let global_start = (piece_index as u64) * self.piece_length;
        self.slices(global_start, piece_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{FileEntry, Info, TorrentFile, TorrentFiles};

    fn torrent_multi() -> TorrentFile {
        TorrentFile {
            info_hash: [0u8; 20],
            announce: None,
            announce_list: vec![],
            info: Info {
                name: "pkg".into(),
                piece_length: 100,
                piece_hashes: vec![[0u8; 20]; 3],
                files: TorrentFiles::Multi {
                    files: vec![
                        FileEntry {
                            length: 150,
                            path: "a.txt".into(),
                        },
                        FileEntry {
                            length: 100,
                            path: "b.txt".into(),
                        },
                        FileEntry {
                            length: 50,
                            path: "c.txt".into(),
                        },
                    ],
                },
                private: false,
            },
        }
    }

    #[test]
    fn single_file_layout() {
        let t = TorrentFile {
            info_hash: [0u8; 20],
            announce: None,
            announce_list: vec![],
            info: Info {
                name: "a.bin".into(),
                piece_length: 100,
                piece_hashes: vec![[0u8; 20]; 2],
                files: TorrentFiles::Single { length: 200 },
                private: false,
            },
        };
        // Use PathBuf::join to construct the expected path so the assertion
        // is identical on Unix and Windows (which would otherwise use `\`).
        let root = PathBuf::from("dl-test-root");
        let l = Layout::from_torrent(root.clone(), &t);
        assert_eq!(l.files.len(), 1);
        assert_eq!(l.files[0].path, root.join("a.bin"));
        assert_eq!(l.files[0].start, 0);
        assert_eq!(l.files[0].length, 200);
    }

    #[test]
    fn multi_file_offsets() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        assert_eq!(l.files[0].start, 0);
        assert_eq!(l.files[1].start, 150);
        assert_eq!(l.files[2].start, 250);
        assert_eq!(l.total_length, 300);
    }

    #[test]
    fn piece_spans_one_file() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Piece 0: bytes 0..100 — all in file 0.
        let s = l.slices_for_piece(0, 100);
        assert_eq!(s, vec![(0, 0, 100)]);
    }

    #[test]
    fn piece_spans_two_files() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Piece 1: bytes 100..200 — file 0 [100..150] + file 1 [0..50]
        let s = l.slices_for_piece(1, 100);
        assert_eq!(s, vec![(0, 100, 50), (1, 0, 50)]);
    }

    #[test]
    fn piece_spans_three_files() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Piece 2: bytes 200..300 (last piece, 100 bytes total) — file 1 [50..100] + file 2 [0..50]
        let s = l.slices_for_piece(2, 100);
        assert_eq!(s, vec![(1, 50, 50), (2, 0, 50)]);
    }
}
