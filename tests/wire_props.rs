//! Property-based fuzz tests for the remaining UNTRUSTED-INPUT wire decoders
//! not already covered by `tests/parser_props.rs` (bencode / peer-message /
//! krpc framing). Every decoder here consumes bytes that arrive straight off
//! the socket from an arbitrary peer, tracker, or DHT node, so the headline
//! invariant is the same: **decoding attacker-controlled bytes must only ever
//! return `Ok`/`Err` — never panic, overflow, slice-OOB, or hang.** proptest
//! turns any panic in the closure into a test failure, so the "never panics"
//! tests just have to drive each parser across a wide spread of inputs.
//!
//! On top of that we round-trip *valid* values through the crate's own public
//! encoders where one exists:
//!   * handshake     → `Handshake::encode` / `Handshake::decode`
//!   * ut_metadata   → `build_metadata_request` → `parse_metadata_response`
//!   * ut_pex        → `build_pex_payload`      → `parse_pex`
//!   * ext handshake → `build_handshake_payload`→ `parse_handshake_payload`
//!   * dht nodes     → `nodes_to_bytes`         → `parse_nodes_bytes`
//!
//! Each "never panics" test is paired with a *structured* variant that seeds
//! correct length prefixes / framing bytes so the strategy actually reaches
//! the parser's interior instead of bouncing off the first length guard.
//!
//! Decoders covered (all reached via the public `rustytorrent::…` surface):
//!   1. peer handshake          — `peer::handshake::Handshake::decode`
//!   2. udp tracker response    — `tracker::udp::parse_announce_response`
//!   3. peer extension messages — `peer::extension::{parse_handshake_payload,
//!                                  parse_metadata_response, parse_pex}`
//!   4. dht compact node/peer   — `dht::krpc::{parse_nodes_bytes,
//!                                  parse_values_list}`
//!   5. BEP 6 fast-extension messages — `peer::message::Message::decode`
//!      for ids 13–17 (SuggestPiece, HaveAll, HaveNone, RejectRequest,
//!      AllowedFast): never-panic + roundtrip.
//!
//! NOTE: the krpc top-level `Message::decode` is already fuzzed in
//! `parser_props.rs`; here we target the *compact contact-info* sub-parsers
//! directly (they are the v4-only 26-byte "nodes" / 6-byte "values" decoders),
//! which the message-level test only reaches incidentally.

use std::net::SocketAddr;

use proptest::collection::vec;
use proptest::prelude::*;

use rustytorrent::dht::krpc::{self, parse_nodes_bytes, parse_values_list};
use rustytorrent::dht::node_id::NodeId;
use rustytorrent::dht::routing::Contact;
use rustytorrent::metainfo::bencode::BencodeValue;
use rustytorrent::peer::extension::{
    build_handshake_payload, build_metadata_request, build_pex_payload, parse_handshake_payload,
    parse_metadata_response, parse_pex,
};
use rustytorrent::peer::handshake::{Handshake, HANDSHAKE_LEN, PSTR, PSTRLEN};
use rustytorrent::tracker::udp::parse_announce_response;

// ---------------------------------------------------------------------------
// Shared strategies
// ---------------------------------------------------------------------------

/// IPv4 socket addrs with a non-zero port (port 0 is dropped on decode, so a
/// zero port would break the round-trips that count entries).
fn arb_v4_addr() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 4]>(), 1u16..=u16::MAX).prop_map(SocketAddr::from)
}

/// IPv6 socket addrs with a non-zero port.
fn arb_v6_addr() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 16]>(), 1u16..=u16::MAX).prop_map(|(octets, port)| {
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
    })
}

/// A 20-byte node id.
fn arb_node_id() -> impl Strategy<Value = NodeId> {
    any::<[u8; 20]>().prop_map(NodeId)
}

/// IPv4-only contacts — the DHT compact wire form is v4-only (BEP 5); the
/// encoder silently drops v6, so a v6 contact would break the round-trip for
/// reasons unrelated to the parser.
fn arb_contact() -> impl Strategy<Value = Contact> {
    (arb_node_id(), arb_v4_addr()).prop_map(|(id, addr)| Contact::new(id, addr))
}

// ---------------------------------------------------------------------------
// 1. peer handshake — never panics + round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes of any length into `Handshake::decode` must return
    /// (Ok/Err) and never panic. Lengths span both sides of the 68-byte
    /// `HANDSHAKE_LEN` guard so we exercise the too-short branch AND the full
    /// field-slicing path.
    #[test]
    fn handshake_decode_never_panics(bytes in vec(any::<u8>(), 0..200)) {
        let _ = Handshake::decode(&bytes);
    }

    /// Structured: a *correct* 68-byte frame (right pstrlen + protocol string)
    /// with random reserved / info_hash / peer_id bodies, so the generator
    /// reaches the interior copy_from_slice path rather than bailing at the
    /// pstrlen / pstr guards. `extra` appends trailing junk (decode must
    /// tolerate over-length input — it only reads the first 68 bytes).
    #[test]
    fn handshake_decode_well_formed_frame_never_panics(
        reserved in any::<[u8; 8]>(),
        info_hash in any::<[u8; 20]>(),
        peer_id in any::<[u8; 20]>(),
        extra in vec(any::<u8>(), 0..40),
    ) {
        let mut buf = Vec::with_capacity(HANDSHAKE_LEN + extra.len());
        buf.push(PSTRLEN);
        buf.extend_from_slice(PSTR);
        buf.extend_from_slice(&reserved);
        buf.extend_from_slice(&info_hash);
        buf.extend_from_slice(&peer_id);
        buf.extend_from_slice(&extra);
        // A genuinely valid frame must decode to exactly the bytes we put in.
        let h = Handshake::decode(&buf).expect("well-formed 68-byte frame must decode");
        prop_assert_eq!(h.reserved, reserved);
        prop_assert_eq!(h.info_hash, info_hash);
        prop_assert_eq!(h.peer_id, peer_id);
    }

    /// Structured negative: a 68-byte frame with a *wrong* first byte (never
    /// the real pstrlen) must be rejected, not panic.
    #[test]
    fn handshake_decode_bad_pstrlen_is_err(
        bad_len in (0u8..=255u8).prop_filter("not the real pstrlen", |b| *b != PSTRLEN),
        body in vec(any::<u8>(), HANDSHAKE_LEN - 1..HANDSHAKE_LEN),
    ) {
        let mut buf = Vec::with_capacity(HANDSHAKE_LEN);
        buf.push(bad_len);
        buf.extend_from_slice(&body);
        prop_assert!(Handshake::decode(&buf).is_err());
    }

    /// Round-trip: anything `Handshake::encode` produces parses back equal.
    #[test]
    fn handshake_roundtrip(
        reserved in any::<[u8; 8]>(),
        info_hash in any::<[u8; 20]>(),
        peer_id in any::<[u8; 20]>(),
    ) {
        // `Handshake::new` pulls reserved bytes from a process-global, so build
        // the struct field-wise to control all bytes deterministically.
        let h = Handshake { reserved, info_hash, peer_id };
        let encoded = h.encode();
        prop_assert_eq!(encoded.len(), HANDSHAKE_LEN);
        let decoded = Handshake::decode(&encoded).expect("encoded handshake must decode");
        prop_assert_eq!(decoded, h);
    }
}

// ---------------------------------------------------------------------------
// 2. udp tracker announce response — never panics
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the UDP-tracker announce-response parser must never
    /// panic. Truncated headers (<20 bytes) and peer payloads that aren't a
    /// multiple of 6 are the prime hazards; the length range straddles the
    /// 20-byte header guard so both the early-return and the chunk-loop paths
    /// are hit.
    #[test]
    fn udp_announce_parse_never_panics(bytes in vec(any::<u8>(), 0..300)) {
        let _ = parse_announce_response(&bytes);
    }

    /// Structured well-formed: a valid 20-byte header followed by exactly
    /// `n` compact (6-byte) peer entries. Must parse `Ok` and recover the
    /// announced fields + every peer, proving the parser interior is reached.
    #[test]
    fn udp_announce_parse_well_formed(
        interval in any::<u32>(),
        leechers in any::<u32>(),
        seeders in any::<u32>(),
        peers in vec((any::<[u8; 4]>(), 1u16..=u16::MAX), 0..32),
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // action = announce
        buf.extend_from_slice(&0u32.to_be_bytes()); // transaction id (unchecked here)
        buf.extend_from_slice(&interval.to_be_bytes());
        buf.extend_from_slice(&leechers.to_be_bytes());
        buf.extend_from_slice(&seeders.to_be_bytes());
        for (ip, port) in &peers {
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        let resp = parse_announce_response(&buf).expect("well-formed announce must parse");
        prop_assert_eq!(resp.seeders, Some(seeders));
        prop_assert_eq!(resp.leechers, Some(leechers));
        prop_assert_eq!(resp.peers.len(), peers.len());
        prop_assert_eq!(resp.interval, std::time::Duration::from_secs(interval as u64));
    }

    /// Structured malformed: a valid header but a peer payload whose length is
    /// deliberately *not* a multiple of 6 must be rejected, not panic.
    #[test]
    fn udp_announce_parse_bad_peer_len_is_err(
        header_tail in vec(any::<u8>(), 12),                 // interval+leechers+seeders
        // 1..=5 trailing bytes can never be a clean multiple of 6.
        ragged in vec(any::<u8>(), 1..=5usize),
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // action
        buf.extend_from_slice(&0u32.to_be_bytes()); // txid
        buf.extend_from_slice(&header_tail);
        buf.extend_from_slice(&ragged);
        prop_assert!(parse_announce_response(&buf).is_err());
    }
}

// ---------------------------------------------------------------------------
// 3. peer extension messages — never panics + round-trips
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the BEP 10 extension-handshake parser must never
    /// panic (it bencode-parses then walks a dict of optional keys).
    #[test]
    fn ext_handshake_parse_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = parse_handshake_payload(&bytes);
    }

    /// Structured: feed the ext-handshake parser *valid bencode* (via the
    /// canonical encoder) that is not necessarily a well-formed handshake,
    /// exercising the `m` / `ut_metadata` / `ut_pex` / `metadata_size`
    /// field-extraction + range-check branches rather than failing at the
    /// outer bencode parse.
    #[test]
    fn ext_handshake_parse_bencode_never_panics(v in arb_bencode()) {
        let bytes = BencodeValue::to_bytes(&v);
        let _ = parse_handshake_payload(&bytes);
    }

    /// Round-trip: our own outgoing handshake payload (both anonymous and not)
    /// must parse back, surfacing the ut_metadata id we advertise.
    #[test]
    fn ext_handshake_roundtrip(anonymous in any::<bool>()) {
        let bytes = build_handshake_payload(anonymous);
        let info = parse_handshake_payload(&bytes).expect("our handshake payload must parse");
        // We always advertise ut_metadata in our `m` dict, so a peer parsing
        // our bytes sees our assigned id back.
        prop_assert!(info.their_ut_metadata_id.is_some());
    }

    /// Arbitrary bytes into the ut_metadata payload parser must never panic.
    #[test]
    fn ut_metadata_parse_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = parse_metadata_response(&bytes);
    }

    /// Structured: a valid bencode dict prefix (msg_type/piece/total_size) with
    /// random trailing raw bytes — the exact shape of a real ut_metadata data
    /// message (dict || piece-bytes). Drives the msg_type match + the
    /// dict/payload split rather than bailing at the bencode parse.
    #[test]
    fn ut_metadata_parse_structured_never_panics(
        msg_type in any::<i64>(),
        piece in any::<i64>(),
        total_size in any::<i64>(),
        trailing in vec(any::<u8>(), 0..64),
    ) {
        use std::collections::BTreeMap;
        let mut d = BTreeMap::new();
        d.insert(b"msg_type".to_vec(), BencodeValue::Int(msg_type));
        d.insert(b"piece".to_vec(), BencodeValue::Int(piece));
        d.insert(b"total_size".to_vec(), BencodeValue::Int(total_size));
        let mut bytes = BencodeValue::Dict(d).to_bytes();
        bytes.extend_from_slice(&trailing); // raw piece bytes follow the dict
        let _ = parse_metadata_response(&bytes);
    }

    /// Round-trip-ish: our own `build_metadata_request` (a request dict) must
    /// parse back. msg_type 0 (request) decodes to `Other` in our model since
    /// we never serve metadata in the bootstrap path — assert it doesn't error.
    #[test]
    fn ut_metadata_request_parses(piece in any::<u32>()) {
        let bytes = build_metadata_request(piece);
        prop_assert!(parse_metadata_response(&bytes).is_ok());
    }

    /// Arbitrary bytes into the ut_pex parser must never panic.
    #[test]
    fn ut_pex_parse_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = parse_pex(&bytes);
    }

    /// Structured: a bencode dict carrying `added` / `added6` byte-strings of
    /// *arbitrary, often-misaligned* length (not guaranteed multiples of 6/18)
    /// plus random flag blobs. This is the adversarial compact-peer case — the
    /// parser must `chunks_exact` past the ragged tail without panicking.
    #[test]
    fn ut_pex_parse_garbage_compact_blobs_never_panics(
        added in vec(any::<u8>(), 0..64),
        added6 in vec(any::<u8>(), 0..64),
        added_f in vec(any::<u8>(), 0..16),
    ) {
        use std::collections::BTreeMap;
        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), BencodeValue::Bytes(added));
        d.insert(b"added6".to_vec(), BencodeValue::Bytes(added6));
        d.insert(b"added.f".to_vec(), BencodeValue::Bytes(added_f));
        let bytes = BencodeValue::Dict(d).to_bytes();
        let _ = parse_pex(&bytes);
    }

    /// Structured well-formed: properly-aligned compact v4 (6-byte) + v6
    /// (18-byte) blobs assembled by hand. Every non-zero-port entry must come
    /// back out, confirming the happy path is genuinely exercised.
    #[test]
    fn ut_pex_parse_aligned_blobs_recovers_peers(
        v4 in vec((any::<[u8; 4]>(), 1u16..=u16::MAX), 0..16),
        v6 in vec((any::<[u8; 16]>(), 1u16..=u16::MAX), 0..16),
    ) {
        use std::collections::BTreeMap;
        let mut added = Vec::new();
        for (ip, port) in &v4 {
            added.extend_from_slice(ip);
            added.extend_from_slice(&port.to_be_bytes());
        }
        let mut added6 = Vec::new();
        for (ip, port) in &v6 {
            added6.extend_from_slice(ip);
            added6.extend_from_slice(&port.to_be_bytes());
        }
        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), BencodeValue::Bytes(added));
        d.insert(b"added6".to_vec(), BencodeValue::Bytes(added6));
        let bytes = BencodeValue::Dict(d).to_bytes();
        let pex = parse_pex(&bytes).expect("aligned compact blobs must parse");
        prop_assert_eq!(pex.added.len(), v4.len() + v6.len());
    }

    /// Round-trip: `build_pex_payload` → `parse_pex` recovers the `added` set
    /// (mixed v4/v6). Dropped peers go into separate keys the parser does not
    /// surface, so only `added` is compared.
    #[test]
    fn ut_pex_roundtrip(
        added in vec(prop_oneof![arb_v4_addr(), arb_v6_addr()], 0..16),
        dropped in vec(arb_v4_addr(), 0..8),
    ) {
        let bytes = build_pex_payload(&added, &dropped);
        let pex = parse_pex(&bytes).expect("our pex payload must parse");
        // Every added peer should round-trip (build splits v4/added & v6/added6,
        // parse re-joins them). Compare as sets — ordering isn't guaranteed.
        for a in &added {
            prop_assert!(pex.added.contains(a), "missing {a} from round-tripped pex");
        }
        prop_assert_eq!(pex.added.len(), added.len());
    }
}

// ---------------------------------------------------------------------------
// 4. dht compact node-info / peer-values — never panics + round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the compact "nodes" decoder (26-byte chunks:
    /// 20 id + 4 ip + 2 port) must never panic. Lengths that aren't multiples
    /// of 26 must be rejected, not crash.
    #[test]
    fn dht_parse_nodes_never_panics(bytes in vec(any::<u8>(), 0..300)) {
        let _ = parse_nodes_bytes(&bytes);
    }

    /// Structured: exactly `n` well-formed 26-byte node records. Must parse
    /// `Ok`; every non-zero-port record is recovered (zero-port records are
    /// dropped by the decoder), proving the chunk loop interior is reached.
    #[test]
    fn dht_parse_nodes_well_formed(
        records in vec((any::<[u8; 20]>(), any::<[u8; 4]>(), 1u16..=u16::MAX), 0..16),
    ) {
        let mut buf = Vec::with_capacity(records.len() * 26);
        for (id, ip, port) in &records {
            buf.extend_from_slice(id);
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        let contacts = parse_nodes_bytes(&buf).expect("aligned 26-byte nodes must parse");
        prop_assert_eq!(contacts.len(), records.len());
    }

    /// Structured malformed: a length deliberately off the 26-byte grid (a
    /// clean multiple of 26 plus 1..=25 extra bytes) must be an error.
    #[test]
    fn dht_parse_nodes_misaligned_is_err(
        full_chunks in vec(any::<u8>(), 0..52),
        extra in vec(any::<u8>(), 1..=25usize),
    ) {
        // Force `full_chunks` onto the 26-grid, then add a ragged tail.
        let aligned_len = (full_chunks.len() / 26) * 26;
        let mut buf = full_chunks[..aligned_len].to_vec();
        buf.extend_from_slice(&extra);
        prop_assert!(!buf.len().is_multiple_of(26)); // sanity on the construction
        prop_assert!(parse_nodes_bytes(&buf).is_err());
    }

    /// Round-trip: `nodes_to_bytes` (v4-only encoder) → `parse_nodes_bytes`
    /// recovers each contact's id + addr. `Contact` derives `PartialEq` over a
    /// `last_seen: Instant` that is reset on decode, so compare the
    /// wire-meaningful projection `(id, addr)` rather than the whole struct.
    #[test]
    fn dht_nodes_roundtrip(contacts in vec(arb_contact(), 0..16)) {
        let bytes = krpc::nodes_to_bytes(&contacts);
        let decoded = parse_nodes_bytes(&bytes).expect("encoded nodes must decode");
        prop_assert_eq!(decoded.len(), contacts.len());
        for (a, b) in contacts.iter().zip(decoded.iter()) {
            prop_assert_eq!(a.id, b.id);
            prop_assert_eq!(a.addr, b.addr);
        }
    }

    /// Arbitrary *bencode* into the compact "values" list decoder must never
    /// panic. `parse_values_list` takes a `BencodeValue` (a list of 6-byte
    /// byte-strings on the wire), so feed it arbitrary trees: non-lists, lists
    /// of wrong-length strings, ints, etc.
    #[test]
    fn dht_parse_values_never_panics(v in arb_bencode()) {
        let _ = parse_values_list(&v);
    }

    /// Structured: a bencode *list* whose elements are byte-strings of random
    /// length (often not 6) — the decoder must skip the non-6-byte and
    /// zero-port entries without panicking, and recover the valid ones.
    #[test]
    fn dht_parse_values_structured(
        good in vec((any::<[u8; 4]>(), 1u16..=u16::MAX), 0..16),
        junk in vec(vec(any::<u8>(), 0..10), 0..8),
    ) {
        let mut items: Vec<BencodeValue> = Vec::new();
        for (ip, port) in &good {
            let mut b = Vec::with_capacity(6);
            b.extend_from_slice(ip);
            b.extend_from_slice(&port.to_be_bytes());
            items.push(BencodeValue::Bytes(b));
        }
        for j in junk {
            // Skip any junk blob that happens to be a valid 6-byte non-zero-port
            // peer, so the count assertion below stays exact.
            let is_accidental_peer =
                j.len() == 6 && u16::from_be_bytes([j[4], j[5]]) != 0;
            if !is_accidental_peer {
                items.push(BencodeValue::Bytes(j));
            }
        }
        let list = BencodeValue::List(items);
        let out = parse_values_list(&list).expect("a bencode list must parse");
        prop_assert_eq!(out.len(), good.len());
    }
}

// ---------------------------------------------------------------------------
// BEP 6 fast-extension message codec (ids 13–17)
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes with a BEP 6 message-id prefix must not panic.
    /// Before BEP 6 was implemented, ids 13–17 returned an error — now they
    /// must decode silently as valid BEP 6 messages or return Err, never panic.
    #[test]
    fn bep6_messages_never_panic(
        id in 13u8..=17u8,
        payload in vec(any::<u8>(), 0..256),
    ) {
        use rustytorrent::peer::message::Message;
        let mut frame = vec![id];
        frame.extend_from_slice(&payload);
        // Just must not panic.
        let _ = Message::decode(&frame);
    }

    /// Well-formed BEP 6 messages (correct payload sizes) parse and roundtrip.
    #[test]
    fn bep6_zero_payload_messages_roundtrip(
        id in prop_oneof![Just(14u8), Just(15u8)], // HaveAll / HaveNone
    ) {
        use rustytorrent::peer::message::Message;
        let frame = vec![id]; // payload-only (no length prefix for decode)
        let msg = Message::decode(&frame).expect("HaveAll/HaveNone with empty payload must parse");
        let encoded = msg.encode();
        // encoded includes the 4-byte length prefix; decode expects payload-only
        // encode() layout: [len: 4 bytes][id: 1 byte][payload: rest]
        // decode() expects:               [id: 1 byte][payload: rest]
        let payload_only = &encoded[4..];
        let roundtrip = Message::decode(payload_only).expect("roundtrip must parse");
        // strip the 4-byte length + 1-byte id prefix for round-trip comparison
        assert_eq!(msg, roundtrip);
    }

    /// RejectRequest roundtrip (same wire layout as Request/Cancel, id 16).
    #[test]
    fn bep6_reject_request_roundtrip(
        index in any::<u32>(),
        begin in any::<u32>(),
        length in any::<u32>(),
    ) {
        use rustytorrent::peer::message::Message;
        let msg = Message::RejectRequest { index, begin, length };
        let encoded = msg.encode();
        // encode() = [len:4][id:1][payload…]; decode() expects [id:1][payload…]
        let payload_only = &encoded[4..];
        let roundtrip = Message::decode(payload_only).expect("RejectRequest must parse");
        assert_eq!(msg, roundtrip);
    }

    /// AllowedFast (id 17) and SuggestPiece (id 13) roundtrip.
    #[test]
    fn bep6_piece_index_messages_roundtrip(
        piece in any::<u32>(),
        id in prop_oneof![Just(17u8), Just(13u8)],
    ) {
        use rustytorrent::peer::message::Message;
        let mut frame = vec![id];
        frame.extend_from_slice(&piece.to_be_bytes());
        let msg = Message::decode(&frame).expect("AllowedFast/SuggestPiece must parse");
        let encoded = msg.encode();
        let payload_only = &encoded[4..]; // [len:4][id:1][payload…] → decode needs [id:1][payload…]
        let roundtrip = Message::decode(payload_only).expect("roundtrip must parse");
        assert_eq!(msg, roundtrip);
    }
}

// ---------------------------------------------------------------------------
// Local bencode strategy (kept independent of parser_props.rs)
// ---------------------------------------------------------------------------

/// Arbitrary *valid* `BencodeValue` trees, bounded well under the parser's
/// hard nesting cap so the generator itself can't blow the stack. Used to feed
/// the bencode-backed decoders (ext handshake, dht values) structurally valid
/// but semantically arbitrary input.
fn arb_bencode() -> impl Strategy<Value = BencodeValue> {
    use proptest::collection::btree_map;
    let leaf = prop_oneof![
        any::<i64>().prop_map(BencodeValue::Int),
        vec(any::<u8>(), 0..32).prop_map(BencodeValue::Bytes),
    ];
    leaf.prop_recursive(5, 48, 6, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..6).prop_map(BencodeValue::List),
            btree_map(vec(any::<u8>(), 0..12), inner, 0..6).prop_map(BencodeValue::Dict),
        ]
    })
}
