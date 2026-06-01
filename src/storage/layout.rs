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
    /// The file paths that match `selectors` (same substring rule as
    /// [`wanted_pieces`]). Used to show the user exactly which files a
    /// `--select` resolved to — an empty result means every selector was
    /// a typo / matched nothing, which is worth surfacing loudly before a
    /// download silently fetches zero bytes. An empty `selectors` returns
    /// every file (the "want everything" default).
    pub fn selected_paths(&self, selectors: &[String]) -> Vec<&std::path::Path> {
        self.files
            .iter()
            .filter(|f| {
                selectors.is_empty() || {
                    let path = f.path.to_string_lossy();
                    selectors.iter().any(|s| path.contains(s.as_str()))
                }
            })
            .map(|f| f.path.as_path())
            .collect()
    }

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

    /// Compute the set of files that must be allocated on disk for a given
    /// selection — i.e. every file that holds at least one byte belonging to
    /// a *wanted* piece. The result is a `Vec<bool>` parallel to
    /// [`Layout::files`] (index `i` true ⇒ file `i` must exist on disk).
    ///
    /// This is intentionally derived from the **same** piece→file span
    /// mapping the write path uses ([`slices_for_piece`]): a file is marked
    /// wanted-for-allocation exactly when some wanted piece's byte range
    /// overlaps it. That makes it correct for boundary/straddle pieces by
    /// construction — a piece that spans a wanted file and an otherwise
    /// unwanted neighbour writes spillover bytes into that neighbour, so the
    /// neighbour appears in the piece's slices and is (correctly) allocated.
    /// Skipping it would break write-back of the straddling wanted piece.
    ///
    /// Empty `selectors` ⇒ every piece is wanted ⇒ every file is wanted,
    /// byte-for-byte the same as the pre-feature default (full preallocation).
    /// Fail-safe: any file we cannot prove receives zero wanted bytes stays
    /// allocated, because it would only be skipped if NO wanted piece's
    /// slices reference it.
    pub fn wanted_files(&self, selectors: &[String]) -> Vec<bool> {
        // Empty selection: short-circuit to "all files wanted" so the disk
        // backend behaves identically to before this feature existed.
        if selectors.is_empty() {
            return vec![true; self.files.len()];
        }
        let wanted_pieces = self.wanted_pieces(selectors);
        let mut wanted_files = vec![false; self.files.len()];
        for (idx, &piece_wanted) in wanted_pieces.iter().enumerate() {
            if !piece_wanted {
                continue;
            }
            let piece_size = self.piece_size(idx);
            for (file_idx, _off, _count) in self.slices_for_piece(idx, piece_size) {
                wanted_files[file_idx] = true;
            }
        }
        wanted_files
    }

    /// Length in bytes of piece `index` (the last piece may be short).
    /// Mirrors the disk backend's `piece_size`; kept here so [`wanted_files`]
    /// can ask the span mapping for a piece's true byte range.
    fn piece_size(&self, index: usize) -> u64 {
        if index + 1 == self.num_pieces {
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

    #[test]
    fn selected_paths_matches_and_reports_empty() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Empty selectors → every file.
        assert_eq!(l.selected_paths(&[]).len(), l.files.len());
        // One match.
        let one = l.selected_paths(&["b.txt".into()]);
        assert_eq!(one.len(), 1);
        assert!(one[0].to_string_lossy().ends_with("b.txt"));
        // No match → empty (the loud-warning trigger in the engine).
        assert!(l.selected_paths(&["nonexistent".into()]).is_empty());
    }

    #[test]
    fn wanted_files_empty_selectors_wants_all_files() {
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Default (no --select): every file allocated, unchanged behaviour.
        assert_eq!(l.wanted_files(&[]), vec![true; l.files.len()]);
    }

    #[test]
    fn wanted_files_skips_fully_unwanted_non_boundary_file() {
        // Files: a.txt [0..150], b.txt [150..250], c.txt [250..300];
        // piece_length 100 → pieces [0..100],[100..200],[200..300].
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        // Select a.txt [0..150]: wanted pieces are 0 ([0..100]) and 1
        // ([100..200]). Piece 1 straddles a.txt and b.txt, so b.txt is
        // allocated despite holding no *selected* content. c.txt [250..300]
        // is touched only by piece 2 (unwanted) → NOT allocated.
        assert_eq!(l.wanted_files(&["a.txt".into()]), vec![true, true, false]);
    }

    #[test]
    fn wanted_files_boundary_neighbour_is_allocated() {
        // Critical straddle case: select ONLY c.txt [250..300]. The single
        // wanted piece is 2 ([200..300]), which overlaps b.txt [150..250]
        // (bytes 200..250) as well as c.txt. So b.txt MUST be allocated — a
        // wanted piece writes spillover into it — even though no selector
        // matched b.txt. a.txt is touched by no wanted piece → skipped.
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        assert_eq!(l.wanted_files(&["c.txt".into()]), vec![false, true, true]);
    }

    #[test]
    fn wanted_files_unmatched_selector_allocates_nothing() {
        // Selector matches no file → no wanted pieces → no file allocated.
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        assert_eq!(
            l.wanted_files(&["nonexistent".into()]),
            vec![false, false, false]
        );
    }

    #[test]
    fn wanted_files_superset_of_selected_content_files() {
        // Invariant: every file that any wanted piece overlaps is allocated.
        // For every selector, the allocated set must cover all files whose
        // byte range intersects a wanted piece — i.e. allocating a file is
        // never skipped while a wanted piece references it.
        let l = Layout::from_torrent("/tmp/dl".into(), &torrent_multi());
        for sel in [vec!["a.txt".to_string()], vec!["b.txt".to_string()]] {
            let pieces = l.wanted_pieces(&sel);
            let files = l.wanted_files(&sel);
            for (idx, &pw) in pieces.iter().enumerate() {
                if !pw {
                    continue;
                }
                let psz = l.piece_size(idx);
                for (file_idx, _, _) in l.slices_for_piece(idx, psz) {
                    assert!(
                        files[file_idx],
                        "file {file_idx} overlapped by wanted piece {idx} but not allocated"
                    );
                }
            }
        }
    }
}
