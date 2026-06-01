//! Property-based tests for the multi-file **virtual offset map** in
//! `storage::layout`. This mapping — which (piece index, intra-piece offset)
//! lands in which (output file, file offset) — is correctness-critical:
//! an off-by-one here does not crash, it *silently corrupts* a multi-file
//! download by writing bytes to the wrong file or offset. The unit tests in
//! `src/storage/layout.rs` pin a handful of hand-computed cases; these tests
//! fuzz the mapping across thousands of random multi-file layouts and assert
//! the structural invariant that ties everything together: the slices produced
//! by [`Layout::slices_for_piece`] across *all* pieces **exactly tile** every
//! file's byte range `[0, file_len)` once — no gaps, no overlaps, in order.
//!
//! Synthetic torrents are built **in memory** (no disk I/O) by constructing
//! `TorrentFile` / `Info` directly — every field is public on the crate's
//! `rustytorrent::metainfo` surface, so no production visibility change was
//! needed. The only non-obvious requirement is that `Info::piece_hashes` must
//! have exactly `ceil(total_length / piece_length)` entries, because
//! `TorrentFile::num_pieces()` is defined as `piece_hashes.len()` (it is *not*
//! recomputed from the lengths). The generator sets that length to the true
//! piece count so `Layout` sees a self-consistent torrent — the same
//! consistency a real parsed `.torrent` always has.
//!
//! Edge cases deliberately in range (this is exactly where offset bugs hide):
//!   * 0-length files (contribute no slices, must not shift neighbours),
//!   * tiny (1-byte) files,
//!   * a short final piece (`total_length % piece_length != 0`),
//!   * a whole torrent shorter than one piece,
//!   * a torrent whose total length is 0 (zero pieces).

use proptest::prelude::*;

use rustytorrent::metainfo::{FileEntry, Info, TorrentFile, TorrentFiles};
use rustytorrent::storage::Layout;

/// One generated synthetic torrent plus the raw inputs the assertions need.
#[derive(Debug, Clone)]
struct Synth {
    torrent: TorrentFile,
    file_lengths: Vec<u64>,
    piece_length: u64,
    total_length: u64,
    num_pieces: usize,
}

/// True number of pieces for a stream of `total` bytes split into
/// `piece_length`-sized pieces: `ceil(total / piece_length)`, and `0` when the
/// stream is empty. This is what a correct `.torrent` records in `pieces`, so
/// the generator uses it to size `piece_hashes`.
fn piece_count(total: u64, piece_length: u64) -> usize {
    if total == 0 {
        0
    } else {
        // div_ceil without overflow risk: total >= 1 here.
        usize::try_from((total - 1) / piece_length + 1).expect("piece count fits usize")
    }
}

/// Byte length of piece `index`: the full `piece_length` for every piece
/// except the last, which holds the remainder. With `num_pieces` derived as
/// `ceil(total / piece_length)`, the last piece is `piece_length` when the
/// total divides evenly and `total % piece_length` otherwise. Only called for
/// `num_pieces > 0`.
fn piece_size(index: usize, num_pieces: usize, total: u64, piece_length: u64) -> u64 {
    debug_assert!(num_pieces > 0 && index < num_pieces);
    if index + 1 == num_pieces {
        let r = total % piece_length;
        if r == 0 {
            piece_length
        } else {
            r
        }
    } else {
        piece_length
    }
}

/// Strategy: a multi-file (or occasionally single-file) torrent.
///
/// * 1..=6 files, each 0..=300 bytes — small on purpose so a single layout
///   spans many pieces and many file boundaries, maximising the chance a
///   boundary bug is hit; 0 and 1 are included to cover the empty/tiny files
///   that break naive offset math.
/// * `piece_length` drawn from a small set of power-of-two-ish values, all
///   well inside the parser's `1..=1<<30` bound. Mixing 3/5/7 in alongside
///   the powers of two guarantees plenty of runs where `total % piece_length`
///   is non-zero, i.e. a genuinely short final piece.
fn synth_strategy() -> impl Strategy<Value = Synth> {
    let file_lengths = prop::collection::vec(0u64..=300, 1..=6);
    let piece_length = prop::sample::select(vec![1u64, 2, 3, 4, 5, 7, 8, 16, 17, 64, 256]);

    (file_lengths, piece_length).prop_map(|(file_lengths, piece_length)| {
        let total_length: u64 = file_lengths.iter().sum();
        let num_pieces = piece_count(total_length, piece_length);

        let entries: Vec<FileEntry> = file_lengths
            .iter()
            .enumerate()
            .map(|(i, &length)| FileEntry {
                length,
                // Distinct, path-safe segment per file; the mapping is
                // index/length-driven so the exact name is irrelevant.
                path: format!("f{i}.bin").into(),
            })
            .collect();

        let torrent = TorrentFile {
            info_hash: [0u8; 20],
            announce: None,
            announce_list: vec![],
            info: Info {
                name: "pkg".into(),
                piece_length,
                // Length MUST equal the real piece count so num_pieces() is
                // self-consistent with the lengths (see module docs).
                piece_hashes: vec![[0u8; 20]; num_pieces],
                files: TorrentFiles::Multi { files: entries },
                private: false,
            },
        };

        Synth {
            torrent,
            file_lengths,
            piece_length,
            total_length,
            num_pieces,
        }
    })
}

proptest! {
    // The strategy is cheap (pure in-memory construction, no I/O), so a high
    // case count is affordable and buys real boundary coverage.
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The headline test: build a layout, walk every piece, and check all four
    /// invariant groups in one pass so a failure reports the whole offending
    /// torrent at once.
    #[test]
    fn offset_map_tiles_every_file_exactly(s in synth_strategy()) {
        let layout = Layout::from_torrent("/synthetic-root".into(), &s.torrent);

        // Sanity: the layout agrees with the torrent we fed it.
        prop_assert_eq!(layout.num_pieces, s.num_pieces);
        prop_assert_eq!(layout.total_length, s.total_length);
        prop_assert_eq!(layout.piece_length, s.piece_length);
        prop_assert_eq!(layout.files.len(), s.file_lengths.len());

        let num_files = s.file_lengths.len();

        // Per file, we rebuild the contiguous high-water mark of bytes written
        // and require each slice to start exactly where the previous one for
        // that file ended. That single check enforces, simultaneously:
        //   * no gaps        (a slice starting past the mark fails),
        //   * no overlaps    (a slice starting before the mark fails),
        //   * in-order cover (coverage only ever extends the mark forward),
        //   * exact start at 0 (the very first slice for a file must hit 0).
        let mut covered = vec![0u64; num_files];

        // Invariant 4 accumulator: total bytes emitted across all slices.
        let mut grand_total: u64 = 0;

        for piece in 0..s.num_pieces {
            let psize = piece_size(piece, s.num_pieces, s.total_length, s.piece_length);
            let slices = layout.slices_for_piece(piece, psize);

            // --- Invariant 1: within-piece coverage & non-emptiness ---
            let mut piece_sum: u64 = 0;
            for &(file_index, file_offset, length) in &slices {
                // Slices are never zero-length (a 0-length file simply produces
                // no slice rather than an empty one). The only legitimately
                // empty *piece* is one of size 0, which cannot occur here
                // because num_pieces = ceil(total/plen) never yields a 0-byte
                // final piece — but assert the contract explicitly anyway.
                prop_assert!(length > 0, "zero-length slice in piece {}", piece);
                piece_sum += length;

                // --- Invariant 2: bounds ---
                prop_assert!(
                    file_index < num_files,
                    "file_index {} out of range ({} files)",
                    file_index, num_files
                );
                let flen = s.file_lengths[file_index];
                prop_assert!(
                    file_offset + length <= flen,
                    "slice ({}, {}, {}) overruns file {} of len {}",
                    file_index, file_offset, length, file_index, flen
                );

                // --- Invariant 3 (per-slice half): contiguous, in-order, no overlap ---
                prop_assert_eq!(
                    file_offset, covered[file_index],
                    "piece {} slice for file {} starts at {} but {} bytes already covered \
                     (gap/overlap/out-of-order)",
                    piece, file_index, file_offset, covered[file_index]
                );
                covered[file_index] += length;
            }

            // The slice lengths for a piece must sum to exactly that piece's
            // size — every byte of the piece is placed, and no more.
            prop_assert_eq!(
                piece_sum, psize,
                "piece {} slices sum to {} but piece_size is {}",
                piece, piece_sum, psize
            );

            grand_total += piece_sum;
        }

        // --- Invariant 3 (whole-file half): each file fully covered ---
        for (i, &flen) in s.file_lengths.iter().enumerate() {
            prop_assert_eq!(
                covered[i], flen,
                "file {} covered {} of {} bytes (gap at end / never fully written)",
                i, covered[i], flen
            );
        }

        // --- Invariant 4: global totals reconcile three ways ---
        let sum_of_files: u64 = s.file_lengths.iter().sum();
        prop_assert_eq!(grand_total, s.total_length);
        prop_assert_eq!(s.total_length, sum_of_files);
    }

    /// Focused last-short-piece check. Force a layout whose total length is
    /// NOT a multiple of `piece_length`, so the final piece is genuinely short,
    /// and assert the final piece's slices sum to the remainder (not a full
    /// `piece_length`). This is the classic spot an offset map gets wrong by
    /// emitting a full-length tail.
    #[test]
    fn short_final_piece_sums_to_remainder(
        // `whole_pieces` full pieces plus a strictly-smaller positive tail.
        // The tail range is derived from the chosen `piece_length`
        // (`1..piece_length`) via flat_map so it is always a valid short tail
        // — no `prop_assume` rejection, which would otherwise discard most
        // cases when `piece_length` is small.
        whole_pieces in 1u64..=8,
        (piece_length, tail) in prop::sample::select(vec![4u64, 8, 16, 64])
            .prop_flat_map(|pl| (Just(pl), 1u64..pl)),
    ) {
        let total = whole_pieces * piece_length + tail;

        // Single file carrying the whole stream is the simplest way to isolate
        // the short-tail arithmetic from cross-file boundaries.
        let num_pieces = piece_count(total, piece_length);
        let torrent = TorrentFile {
            info_hash: [0u8; 20],
            announce: None,
            announce_list: vec![],
            info: Info {
                name: "pkg".into(),
                piece_length,
                piece_hashes: vec![[0u8; 20]; num_pieces],
                files: TorrentFiles::Multi {
                    files: vec![FileEntry { length: total, path: "only.bin".into() }],
                },
                private: false,
            },
        };
        let layout = Layout::from_torrent("/synthetic-root".into(), &torrent);

        let last = num_pieces - 1;
        let psize = piece_size(last, num_pieces, total, piece_length);
        prop_assert_eq!(psize, tail, "computed last piece size wrong");

        let slices = layout.slices_for_piece(last, psize);
        let s: u64 = slices.iter().map(|&(_, _, len)| len).sum();
        prop_assert_eq!(s, tail, "final piece emitted {} bytes, expected tail {}", s, tail);
    }
}

/// A non-proptest sanity test proving the generator actually exercises the
/// multi-file case it claims to (guards against the strategy degenerating to
/// trivial single-file or zero-piece layouts that would make the headline
/// property vacuous). We sample many torrents and require that at least one
/// has >1 file, at least one has a short final piece, and at least one has a
/// 0-length file in it.
#[test]
fn generator_actually_covers_multifile_and_edges() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let strat = synth_strategy();

    let mut saw_multifile = false;
    let mut saw_short_final = false;
    let mut saw_zero_len_file = false;
    let mut saw_nonempty = false;

    for _ in 0..512 {
        let tree = strat
            .new_tree(&mut runner)
            .expect("strategy produces a value");
        let s = tree.current();

        if s.file_lengths.len() > 1 {
            saw_multifile = true;
        }
        if s.file_lengths.contains(&0) {
            saw_zero_len_file = true;
        }
        if s.total_length > 0 {
            saw_nonempty = true;
            if !s.total_length.is_multiple_of(s.piece_length) {
                saw_short_final = true;
            }
        }
    }

    assert!(
        saw_multifile,
        "generator never produced a multi-file torrent"
    );
    assert!(saw_nonempty, "generator never produced a non-empty torrent");
    assert!(
        saw_short_final,
        "generator never produced a short final piece"
    );
    assert!(
        saw_zero_len_file,
        "generator never produced a 0-length file"
    );
}
