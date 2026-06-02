//! Property-based fuzz tests for the UNTRUSTED-INPUT metainfo parsers:
//! the `.torrent` decoder (`TorrentFile::from_bytes`), the magnet
//! info-dict path (`TorrentFile::from_info_dict_bytes`), and the magnet
//! URI parser (`MagnetLink::parse`).
//!
//! These three entry points consume bytes that arrive from a hostile
//! `.torrent` file, from info-dict bytes fetched via BEP 9 ut_metadata
//! off arbitrary peers, or from a magnet URI pasted by the user. They sit
//! at the trust boundary, so two classes of invariant matter:
//!
//!   1. **Liveness:** decoding attacker-controlled bytes must only ever
//!      return `Ok`/`Err` — never panic, overflow, or hang. proptest
//!      turns any panic (an arithmetic overflow, a slice-index OOB, an
//!      `unwrap` on `None`) into a test failure, so the "never panics"
//!      tests just have to drive the parser across a wide input spread.
//!
//!   2. **Security bounds:** for any input the parser *accepts*, the
//!      resulting `TorrentFile` must be safe to act on. Concretely
//!      (verified against `src/metainfo/torrent.rs`): `info.name` is a
//!      single safe path component — never empty, `.`, `..`, and never
//!      containing `/` or `\` (else `storage::Layout` joins it onto the
//!      download root and escapes the directory — `root.join("/etc/x")`
//!      discards `root`); every multi-file path segment is likewise a
//!      safe component; and `info.piece_length` is in
//!      `1..=1_073_741_824` (1 GiB) — zero is degenerate and an enormous
//!      value overflows the `piece_index * piece_length` offset math and
//!      drives oversized allocations.
//!
//! The matching private guard is `is_unsafe_path_component`; we cannot
//! call it, so we assert the bound holds through the public parse result
//! instead — i.e. a hostile field must cause `Err`, not a `TorrentFile`
//! that violates the bound.
//!
//! To actually reach the validators (rather than bouncing off the first
//! bencode error) the structured strategies build *valid* bencode dicts.
//! Dicts are assembled as `BencodeValue::Dict(BTreeMap)` and serialized
//! with the crate's own canonical `to_bytes`, which emits keys in the
//! lexicographic byte order the parser's dict reader requires.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::*;

use rustytorrent::magnet::MagnetLink;
use rustytorrent::metainfo::torrent::TorrentFile;
use rustytorrent::metainfo::{BencodeValue, TorrentFiles};

// The piece-length ceiling enforced by `Info::from_value` (1 GiB).
const MAX_PIECE_LENGTH: u64 = 1 << 30;

// ---------------------------------------------------------------------------
// Bencode-building helpers (test-side encoder via the public `to_bytes`)
// ---------------------------------------------------------------------------

/// Build a bencode dict from `(key, value)` pairs. Keys are inserted into
/// a `BTreeMap`, so the subsequent `to_bytes` emits them in the
/// lexicographic order the parser's dict reader enforces — regardless of
/// the order we list them here.
fn bdict(pairs: Vec<(&[u8], BencodeValue)>) -> BencodeValue {
    let mut m: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(k.to_vec(), v);
    }
    BencodeValue::Dict(m)
}

fn bbytes(b: &[u8]) -> BencodeValue {
    BencodeValue::Bytes(b.to_vec())
}

fn bint(i: i64) -> BencodeValue {
    BencodeValue::Int(i)
}

// ---------------------------------------------------------------------------
// Strategies for the hostile fields
// ---------------------------------------------------------------------------

/// Candidate `name` / path-segment values. Deliberately mixes the
/// traversal primitives the validator must reject (`..`, `.`, separators,
/// empty, absolute-looking, embedded separators) with plainly safe names
/// so accepted torrents are also exercised.
fn arb_component() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("..".to_string()),
        Just(".".to_string()),
        Just("/".to_string()),
        Just("\\".to_string()),
        Just(String::new()),
        Just("/etc/passwd".to_string()),
        Just("../evil".to_string()),
        Just("a/b".to_string()),
        Just("a\\b".to_string()),
        Just("..\\..\\x".to_string()),
        Just("file.bin".to_string()),
        Just("dir".to_string()),
        Just("normal_name-123".to_string()),
        // A short freeform string can independently land on a separator or
        // a dot-run, widening coverage beyond the fixed cases above.
        "[\\\\/.a-z]{0,6}",
    ]
}

/// Candidate `piece length` integers, as the raw bencode `i64`. Spans the
/// boundary cases the cap cares about: 0 and negatives (rejected), the
/// in-range edges 1 / 16384 / exactly the cap, just over the cap, and an
/// absurd near-`i64::MAX` value (rejected as > cap).
fn arb_piece_length() -> impl Strategy<Value = i64> {
    prop_oneof![
        Just(0i64),
        Just(-1i64),
        Just(-16384i64),
        Just(i64::MIN),
        Just(1i64),
        Just(16384i64),
        Just(MAX_PIECE_LENGTH as i64),     // exactly 1 GiB — accepted
        Just(MAX_PIECE_LENGTH as i64 + 1), // one over — rejected
        Just(9_999_999_999i64),            // ~9.3 GiB — rejected
        Just(i64::MAX),                    // absurd — rejected
        Just(262_144i64),                  // 256 KiB — a normal real value
        Just(1_048_576i64),                // 1 MiB — a normal real value
    ]
}

/// `pieces` is a byte string whose length the parser requires to be a
/// multiple of 20. Mix valid multiples (incl. empty and several hashes)
/// with deliberately-misaligned lengths to exercise the `% 20` check.
fn arb_pieces() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..80).prop_map(|mut v| {
            let trim = v.len() % 20;
            v.truncate(v.len() - trim);
            v
        }),
        vec(any::<u8>(), 0..80), // possibly-misaligned
    ]
}

/// One multi-file entry: `d6:lengthi<n>e4:pathl<seg>...ee`.
fn arb_file_entry() -> impl Strategy<Value = BencodeValue> {
    (any::<i64>(), vec(arb_component(), 1..3)).prop_map(|(len, segs)| {
        let path = BencodeValue::List(segs.iter().map(|s| bbytes(s.as_bytes())).collect());
        bdict(vec![(b"length", bint(len)), (b"path", path)])
    })
}

/// A structurally valid `.torrent` byte buffer with fuzzed hostile fields.
/// Randomly single-file (carries `length`) or multi-file (carries
/// `files`), with a fuzzed `name`, `piece length`, and `pieces`, plus an
/// optional `announce`. The bytes are real canonical bencode, so parsing
/// proceeds past the structural reader into the security validators.
fn arb_torrent_bytes() -> impl Strategy<Value = Vec<u8>> {
    let single = (
        arb_component(),
        arb_piece_length(),
        arb_pieces(),
        any::<i64>(),
    )
        .prop_map(|(name, plen, pieces, length)| {
            bdict(vec![
                (b"length", bint(length)),
                (b"name", bbytes(name.as_bytes())),
                (b"piece length", bint(plen)),
                (b"pieces", bbytes(&pieces)),
            ])
        });

    let multi = (
        arb_component(),
        arb_piece_length(),
        arb_pieces(),
        vec(arb_file_entry(), 1..4),
    )
        .prop_map(|(name, plen, pieces, files)| {
            bdict(vec![
                (b"files", BencodeValue::List(files)),
                (b"name", bbytes(name.as_bytes())),
                (b"piece length", bint(plen)),
                (b"pieces", bbytes(&pieces)),
            ])
        });

    let info = prop_oneof![single, multi];

    (info, prop::option::of("[a-z]{1,8}")).prop_map(|(info, ann)| {
        let mut pairs: Vec<(&[u8], BencodeValue)> = vec![(b"info", info)];
        if let Some(a) = ann {
            let url = format!("http://tracker.test/{a}");
            pairs.push((b"announce", bbytes(url.as_bytes())));
        }
        bdict(pairs).to_bytes()
    })
}

// ---------------------------------------------------------------------------
// Reusable invariant assertion
// ---------------------------------------------------------------------------

/// Assert the security bounds on an *accepted* torrent. Returns a
/// `Result` so it threads cleanly through proptest's `?`.
fn assert_torrent_safe(t: &TorrentFile) -> Result<(), TestCaseError> {
    // (a) name is a safe single component.
    let name = &t.info.name;
    prop_assert!(!name.is_empty(), "accepted name is empty: {name:?}");
    prop_assert!(name != ".", "accepted name is `.`: {name:?}");
    prop_assert!(name != "..", "accepted name is `..`: {name:?}");
    prop_assert!(
        !name.contains('/') && !name.contains('\\'),
        "accepted name contains a separator: {name:?}"
    );

    // (b) every multi-file path segment is a safe component.
    if let TorrentFiles::Multi { files } = &t.info.files {
        for fe in files {
            for seg in fe.path.iter() {
                let s = seg.to_string_lossy();
                prop_assert!(!s.is_empty(), "empty path segment in {:?}", fe.path);
                prop_assert!(s != ".", "`.` path segment in {:?}", fe.path);
                prop_assert!(s != "..", "`..` path segment in {:?}", fe.path);
                prop_assert!(
                    !s.contains('/') && !s.contains('\\'),
                    "separator in path segment {s:?} of {:?}",
                    fe.path
                );
            }
            // The reconstructed path must stay relative — an absolute path
            // would escape the download root on join.
            prop_assert!(
                fe.path.is_relative(),
                "accepted absolute file path: {:?}",
                fe.path
            );
        }
    }

    // (c) piece_length within the enforced bound.
    prop_assert!(
        (1..=MAX_PIECE_LENGTH).contains(&t.info.piece_length),
        "piece_length {} outside 1..=2^30",
        t.info.piece_length
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. TorrentFile::from_bytes never panics on arbitrary input
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the `.torrent` parser must return (Ok/Err) and
    /// never panic, overflow, or hang.
    #[test]
    fn torrent_from_bytes_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = TorrentFile::from_bytes(&bytes);
    }

    /// Seeded with bencode framing bytes so the generator spends more time
    /// in the parser's structural and validation paths rather than bailing
    /// on the first non-bencode byte.
    #[test]
    fn torrent_from_bytes_never_panics_structured(
        bytes in vec(
            prop_oneof![
                Just(b'i'), Just(b'l'), Just(b'd'), Just(b'e'), Just(b':'), Just(b'-'),
                (b'0'..=b'9'),
                any::<u8>(),
            ],
            0..512,
        )
    ) {
        let _ = TorrentFile::from_bytes(&bytes);
    }
}

// ---------------------------------------------------------------------------
// 2 & 3. Structured torrents reach the validators; bounds hold on accept
// ---------------------------------------------------------------------------

proptest! {
    /// Feed *valid bencode* `.torrent` buffers with fuzzed hostile fields.
    /// Whatever the parser decides, it must not panic — and crucially every
    /// **accepted** torrent must satisfy the path-traversal and piece-length
    /// bounds. A hostile field must surface as `Err`, never as a returned
    /// `TorrentFile` that could escape the download dir or overflow.
    #[test]
    fn torrent_structured_upholds_security_bounds(bytes in arb_torrent_bytes()) {
        match TorrentFile::from_bytes(&bytes) {
            Ok(t) => assert_torrent_safe(&t)?,
            Err(_) => { /* rejected — acceptable */ }
        }
    }

    /// Same invariants through the magnet info-dict entry point
    /// (`from_info_dict_bytes`). That function recomputes SHA1 over the
    /// info bytes and rejects a mismatch, so we pass the real digest of the
    /// info dict we built; this drives past the hash gate into the shared
    /// `Info::from_value` validator.
    #[test]
    fn info_dict_bytes_upholds_security_bounds(
        name in arb_component(),
        plen in arb_piece_length(),
        pieces in arb_pieces(),
        length in any::<i64>(),
    ) {
        let info = bdict(vec![
            (b"length", bint(length)),
            (b"name", bbytes(name.as_bytes())),
            (b"piece length", bint(plen)),
            (b"pieces", bbytes(&pieces)),
        ]);
        let info_bytes = info.to_bytes();
        let info_hash = sha1_20(&info_bytes);

        match TorrentFile::from_info_dict_bytes(&info_bytes, info_hash, Vec::new()) {
            Ok(t) => {
                assert_torrent_safe(&t)?;
                // The hash gate must have passed through unchanged.
                prop_assert_eq!(t.info_hash, info_hash);
            }
            Err(_) => { /* rejected by name/piece-length/pieces validators */ }
        }
    }

    /// Positive control: a torrent built entirely from *safe* fields and an
    /// in-range piece length must be **accepted** — guarding against the
    /// validators being so strict they reject everything (which would make
    /// the bound-checks above vacuously pass).
    ///
    /// `nhashes` is derived from `length` and `plen` (= ceil(length/plen))
    /// so every generated combination is structurally valid and the check
    /// added in `Info::from_value` always passes here.
    #[test]
    fn safe_torrent_is_accepted(
        name in "[a-z][a-z0-9_.-]{0,12}",
        plen in prop_oneof![Just(16_384i64), Just(262_144i64), Just(MAX_PIECE_LENGTH as i64)],
        length in 1i64..1_000_000,
    ) {
        // `name` regex still admits a bare "." run; skip those so the
        // positive control only feeds genuinely safe names.
        prop_assume!(name != "." && name != "..");
        // Derive nhashes so the piece-hash count always equals
        // ceil(length / piece_length) — the parser validates this invariant.
        let nhashes = (length as u64).div_ceil(plen as u64) as usize;
        let pieces = vec![0u8; nhashes * 20];
        let info = bdict(vec![
            (b"length", bint(length)),
            (b"name", bbytes(name.as_bytes())),
            (b"piece length", bint(plen)),
            (b"pieces", bbytes(&pieces)),
        ]);
        let bytes = bdict(vec![(b"info", info)]).to_bytes();
        let t = TorrentFile::from_bytes(&bytes)
            .expect("a torrent with safe name + in-range piece length must parse");
        assert_torrent_safe(&t)?;
        prop_assert_eq!(&t.info.name, &name);
        prop_assert_eq!(t.info.piece_length, plen as u64);
    }
}

// ---------------------------------------------------------------------------
// 4. MagnetLink::parse — never panics + accepted-hash invariant
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary strings into the magnet parser must return (Ok/Err) and
    /// never panic.
    #[test]
    fn magnet_parse_never_panics(s in ".*") {
        let _ = MagnetLink::parse(&s);
    }

    /// Seeded with magnet framing tokens (`magnet:?`, the `xt`/`tr`/`dn`
    /// keys, `urn:btih:`, hex/base32 alphabets, percent escapes) so the
    /// generator drives the info-hash, percent-decode, and key-dispatch
    /// paths rather than bailing on the scheme prefix.
    #[test]
    fn magnet_parse_never_panics_structured(
        s in proptest::string::string_regex(
            "magnet:\\?(xt=urn:btih:[0-9a-zA-Z%:]{0,45}|tr=[a-z%0-9:.]{0,12}|dn=[a-z%0-9+]{0,8}|xl=[0-9]{0,6}|&){0,8}"
        ).unwrap()
    ) {
        let _ = MagnetLink::parse(&s);
    }

    /// For any **accepted** magnet, the btih info_hash is exactly 20 bytes.
    /// (`info_hash` is a `[u8; 20]`, so this is enforced by the type — we
    /// assert its length explicitly to pin the contract, and confirm the
    /// hex/base32 decoders both yield the full 20.) Seed structured magnets
    /// with a fuzzed hash, optional trackers, and an optional display name.
    #[test]
    fn magnet_accepted_hash_is_20_bytes(
        hash in arb_btih(),
        trackers in vec("[a-z][a-z0-9.]{0,8}", 0..3),
        dn in prop::option::of("[a-zA-Z0-9]{0,8}"),
    ) {
        let mut uri = format!("magnet:?xt=urn:btih:{hash}");
        for tr in &trackers {
            uri.push_str("&tr=http%3A%2F%2F");
            uri.push_str(tr);
            uri.push_str("%2Fannounce");
        }
        if let Some(name) = &dn {
            uri.push_str("&dn=");
            uri.push_str(name);
        }

        match MagnetLink::parse(&uri) {
            Ok(m) => {
                prop_assert_eq!(m.info_hash.len(), 20);
                prop_assert_eq!(m.trackers.len(), trackers.len());
                if let Some(name) = dn {
                    prop_assert_eq!(m.display_name.as_deref(), Some(name.as_str()));
                }
            }
            Err(_) => { /* malformed hash etc. — acceptable */ }
        }
    }
}

/// A candidate btih hash payload: well-formed 40-char hex / 32-char
/// base32, plus malformed lengths and out-of-alphabet chars to exercise
/// the reject paths.
fn arb_btih() -> impl Strategy<Value = String> {
    prop_oneof![
        "[0-9a-f]{40}",      // valid lowercase hex
        "[0-9A-F]{40}",      // valid uppercase hex
        "[A-Z2-7]{32}",      // valid base32
        "[a-z2-7]{32}",      // valid lowercase base32
        "[0-9a-fA-F]{0,50}", // wrong-length hex-ish
        "[A-Za-z2-7]{0,50}", // wrong-length base32-ish
        "[g-z]{40}",         // 40 chars, non-hex / non-base32
    ]
}

// ---------------------------------------------------------------------------
// Local SHA1 (drive the `from_info_dict_bytes` hash gate)
// ---------------------------------------------------------------------------

fn sha1_20(bytes: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}
