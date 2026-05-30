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

    /// Compute which pieces are *wanted* given a set of file-path
    /// selectors (used for selective download). A file is selected when
    /// its path contains any of the `selectors` substrings; a piece is
    /// wanted when its byte range overlaps any selected file. An empty
    /// `selectors` slice means "want everything" — the default, and the
    /// only case the rest of the engine ever saw before this feature, so
    /// it returns an all-`true` mask byte-for-byte identical to no
    /// selection at all.
    ///
    /// Boundary pieces that straddle a wanted and an unwanted file are
    /// wanted (we need the whole piece to reconstruct the wanted file);
    /// the unwanted file just receives the spillover bytes, which is
    /// standard BitTorrent behaviour.
    pub fn wanted_pieces(&self, selectors: &[String]) -> Vec<bool> {
        if selectors.is_empty() {
            return vec![true; self.num_pieces];
        }
        let selected: Vec<&FileSpan> = self
            .files
            .iter()
            .filter(|f| {
                let path = f.path.to_string_lossy();
                selectors.iter().any(|s| path.contains(s.as_str()))
            })
            .collect();

        let mut wanted = vec![false; self.num_pieces];
        for (idx, w) in wanted.iter_mut().enumerate() {
            let piece_start = (idx as u64) * self.piece_length;
            let piece_end = (piece_start + self.piece_length).min(self.total_length);
            *w = selected
                .iter()
                .any(|f| f.start < piece_end && piece_start < f.end());
        }
        wanted
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

    #[test]
    fn wanted_empty_selectors_wants_everything() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        assert_eq!(l.wanted_pieces(&[]), vec![true; l.num_pieces]);
    }

    #[test]
    fn wanted_selects_overlapping_pieces_only() {
        // Files: a.txt [0..150], b.txt [150..250], c.txt [250..300];
        // piece_length 100 → pieces cover [0..100],[100..200],[200..300].
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Select only c.txt ([250..300]) → only piece 2 ([200..300]) overlaps.
        assert_eq!(l.wanted_pieces(&["c.txt".into()]), vec![false, false, true]);
        // Select b.txt ([150..250]) → pieces 1 ([100..200]) and 2 ([200..300]).
        assert_eq!(l.wanted_pieces(&["b.txt".into()]), vec![false, true, true]);
        // Select a.txt ([0..150]) → pieces 0 ([0..100]) and 1 ([100..200]).
        assert_eq!(l.wanted_pieces(&["a.txt".into()]), vec![true, true, false]);
    }

    #[test]
    fn wanted_unmatched_selector_wants_nothing() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        assert_eq!(
            l.wanted_pieces(&["nonexistent".into()]),
            vec![false, false, false]
        );
    }
}
