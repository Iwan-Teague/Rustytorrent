//! Property-based fuzz tests for the three UNTRUSTED-INPUT parsers:
//! bencode (metainfo), the peer-wire message framing, and the DHT KRPC
//! decoder. Every one of these consumes bytes that arrive from arbitrary
//! peers / trackers / DHT nodes, so the headline invariant is simple:
//! **decoding attacker-controlled bytes must never panic or hang** — it may
//! only ever return `Ok` or `Err`. proptest turns a panic (including an
//! arithmetic overflow, slice-index OOB, or `unwrap` on `None`) into a test
//! failure automatically, so the "never panics" tests just have to drive the
//! parser across a wide spread of inputs and return.
//!
//! On top of that we assert round-trips for *valid* values: anything the
//! crate's own canonical encoder produces must parse back to an equal value.
//! The encoders used are the real public ones:
//!   * bencode  → `BencodeValue::to_bytes`
//!   * peer msg → `peer::message::Message::encode`
//!   * krpc     → `dht::krpc::Message::encode`

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

use rustytorrent::dht::krpc::{self, Query, Response};
use rustytorrent::dht::node_id::NodeId;
use rustytorrent::dht::routing::Contact;
use rustytorrent::metainfo::BencodeValue;
use rustytorrent::peer::message::Message;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// A recursive strategy that builds arbitrary *valid* `BencodeValue` trees:
/// ints, byte-strings, lists and dicts. Depth is bounded well under the
/// parser's hard nesting cap of 100 so the generator can't itself blow the
/// stack while still exercising real nesting.
fn arb_bencode() -> impl Strategy<Value = BencodeValue> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(BencodeValue::Int),
        vec(any::<u8>(), 0..32).prop_map(BencodeValue::Bytes),
    ];
    leaf.prop_recursive(
        6,  // max depth of nesting
        64, // max total nodes
        8,  // max items per collection node
        |inner| {
            prop_oneof![
                vec(inner.clone(), 0..8).prop_map(BencodeValue::List),
                // BTreeMap keys are unique by construction, matching the
                // parser's "keys sorted & non-duplicated" requirement.
                btree_map(vec(any::<u8>(), 0..16), inner, 0..8).prop_map(BencodeValue::Dict),
            ]
        },
    )
}

/// 20-byte node IDs / info-hashes.
fn arb_id20() -> impl Strategy<Value = [u8; 20]> {
    any::<[u8; 20]>()
}

fn arb_node_id() -> impl Strategy<Value = NodeId> {
    arb_id20().prop_map(NodeId)
}

/// IPv4-only contacts — the compact wire form is v4-only (BEP 5) and the
/// encoder silently drops anything else, so generating v6 here would break
/// the round-trip for reasons unrelated to the parser.
fn arb_contact() -> impl Strategy<Value = Contact> {
    (arb_node_id(), any::<[u8; 4]>(), 1u16..=u16::MAX).prop_map(|(id, ip, port)| {
        let addr = std::net::SocketAddr::from((ip, port));
        Contact::new(id, addr)
    })
}

/// IPv4 socket addrs with a non-zero port (port 0 is dropped on decode).
fn arb_v4_addr() -> impl Strategy<Value = std::net::SocketAddr> {
    (any::<[u8; 4]>(), 1u16..=u16::MAX).prop_map(std::net::SocketAddr::from)
}

/// Every peer-wire `Message` variant, with bounded payload sizes.
fn arb_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        Just(Message::KeepAlive),
        Just(Message::Choke),
        Just(Message::Unchoke),
        Just(Message::Interested),
        Just(Message::NotInterested),
        any::<u32>().prop_map(Message::Have),
        vec(any::<u8>(), 0..64).prop_map(Message::Bitfield),
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(index, begin, length)| {
            Message::Request {
                index,
                begin,
                length,
            }
        }),
        (any::<u32>(), any::<u32>(), vec(any::<u8>(), 0..64))
            .prop_map(|(index, begin, data)| { Message::Piece { index, begin, data } }),
        (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(index, begin, length)| {
            Message::Cancel {
                index,
                begin,
                length,
            }
        }),
        (any::<u8>(), vec(any::<u8>(), 0..64))
            .prop_map(|(ext_id, payload)| { Message::Extended { ext_id, payload } }),
    ]
}

/// Every KRPC `Query`.
fn arb_query() -> impl Strategy<Value = Query> {
    prop_oneof![
        arb_node_id().prop_map(|id| Query::Ping { id }),
        (arb_node_id(), arb_node_id()).prop_map(|(id, target)| Query::FindNode { id, target }),
        (arb_node_id(), arb_id20()).prop_map(|(id, info_hash)| Query::GetPeers { id, info_hash }),
        (
            arb_node_id(),
            arb_id20(),
            any::<u16>(),
            vec(any::<u8>(), 0..32),
            any::<bool>(),
        )
            .prop_map(|(id, info_hash, port, token, implied_port)| {
                Query::AnnouncePeer {
                    id,
                    info_hash,
                    port,
                    token,
                    implied_port,
                }
            }),
    ]
}

/// KRPC `Response` variants that survive an encode→decode round-trip.
///
/// NOTE on `Response::Nodes`: the encoder emits an empty `nodes` string for
/// an empty contact list, but on decode an empty `nodes` (with no `values`
/// and no `token`) is indistinguishable from a plain `Id` reply, so the
/// decoder yields `Response::Id`. To keep this a clean round-trip we require
/// at least one node for the `Nodes`/`PeersNodes` variants.
fn arb_response() -> impl Strategy<Value = Response> {
    prop_oneof![
        arb_node_id().prop_map(|id| Response::Id { id }),
        (arb_node_id(), vec(arb_contact(), 1..6))
            .prop_map(|(id, nodes)| Response::Nodes { id, nodes }),
        (
            arb_node_id(),
            vec(any::<u8>(), 0..16),
            vec(arb_v4_addr(), 1..6)
        )
            .prop_map(|(id, token, values)| Response::Peers { id, token, values }),
        (
            arb_node_id(),
            vec(any::<u8>(), 0..16),
            vec(arb_contact(), 1..6)
        )
            .prop_map(|(id, token, nodes)| Response::PeersNodes { id, token, nodes }),
    ]
}

/// Any KRPC `Message`.
fn arb_krpc_message() -> impl Strategy<Value = krpc::Message> {
    prop_oneof![
        (vec(any::<u8>(), 0..8), arb_query()).prop_map(|(transaction_id, query)| {
            krpc::Message::Query {
                transaction_id,
                query,
            }
        }),
        (vec(any::<u8>(), 0..8), arb_response()).prop_map(|(transaction_id, response)| {
            krpc::Message::Response {
                transaction_id,
                response,
            }
        }),
        (vec(any::<u8>(), 0..8), any::<i64>(), ".*").prop_map(|(transaction_id, code, message)| {
            krpc::Message::Error {
                transaction_id,
                code,
                message,
            }
        }),
    ]
}

// ---------------------------------------------------------------------------
// 1. bencode never panics
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the bencode parser must return (Ok/Err) and never
    /// panic, overflow, or hang. proptest fails the case if the closure panics.
    #[test]
    fn bencode_parse_all_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        // Drive both public entry points. The result is intentionally ignored;
        // we only care that control returns here.
        let _ = BencodeValue::parse_all(&bytes);
        let _ = BencodeValue::parse(&bytes);
    }

    /// Seeded with bencode framing bytes so the generator spends more time in
    /// the parser's *structural* paths (lengths, nesting, terminators) instead
    /// of bailing on the first non-bencode byte.
    #[test]
    fn bencode_parse_all_never_panics_structured(
        bytes in vec(
            prop_oneof![
                Just(b'i'), Just(b'l'), Just(b'd'), Just(b'e'), Just(b':'), Just(b'-'),
                (b'0'..=b'9'),
                any::<u8>(),
            ],
            0..512,
        )
    ) {
        let _ = BencodeValue::parse_all(&bytes);
        let _ = BencodeValue::parse(&bytes);
    }
}

// ---------------------------------------------------------------------------
// 2. bencode round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// Every valid tree the canonical encoder (`to_bytes`) produces must parse
    /// back to an equal value via `parse_all`.
    #[test]
    fn bencode_roundtrip(v in arb_bencode()) {
        let encoded = v.to_bytes();
        let decoded = BencodeValue::parse_all(&encoded)
            .expect("canonical bencode must parse");
        prop_assert_eq!(decoded, v);
    }
}

// ---------------------------------------------------------------------------
// 3. peer message: never panics + round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary frame bytes into `Message::decode` must never panic.
    #[test]
    fn message_decode_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = Message::decode(&bytes);
    }

    /// Seeded with valid message-id leading bytes so we frequently hit the
    /// length-checked decode arms (Have/Request/Piece/Cancel/Extended) rather
    /// than bouncing off "unknown message id".
    #[test]
    fn message_decode_never_panics_structured(
        id in prop_oneof![0u8..=8u8, Just(20u8), any::<u8>()],
        body in vec(any::<u8>(), 0..64),
    ) {
        let mut frame = Vec::with_capacity(1 + body.len());
        frame.push(id);
        frame.extend_from_slice(&body);
        let _ = Message::decode(&frame);
    }

    /// Constructed messages round-trip. `encode` includes the 4-byte length
    /// prefix; `decode` expects the payload *without* it, so strip [4..].
    #[test]
    fn message_roundtrip(m in arb_message()) {
        let encoded = m.encode();
        prop_assert!(encoded.len() >= 4);
        let decoded = Message::decode(&encoded[4..]).expect("encoded message must decode");
        prop_assert_eq!(decoded, m);
    }
}

// ---------------------------------------------------------------------------
// 4. krpc never panics (+ round-trip for good measure)
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary bytes into the KRPC decode entry point must never panic.
    #[test]
    fn krpc_decode_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = krpc::Message::decode(&bytes);
    }

    /// Bencoded-but-arbitrary input: feed the KRPC decoder valid bencode that
    /// is *not* necessarily a well-formed KRPC message, exercising the dict
    /// field-extraction paths (missing/wrong-typed `t`/`y`/`q`/`a`/...).
    #[test]
    fn krpc_decode_arbitrary_bencode_never_panics(v in arb_bencode()) {
        let bytes = v.to_bytes();
        let _ = krpc::Message::decode(&bytes);
    }

    /// Constructed KRPC messages round-trip through encode→decode.
    ///
    /// `Contact` derives `PartialEq` over a `last_seen: Instant` that is reset
    /// to `Instant::now()` on decode, so a direct `Message` equality would
    /// spuriously fail for the node-bearing responses. We therefore compare on
    /// the wire-meaningful projection — node `(id, addr)` pairs — and use exact
    /// equality everywhere else.
    #[test]
    fn krpc_roundtrip(m in arb_krpc_message()) {
        let encoded = m.encode();
        let decoded = krpc::Message::decode(&encoded).expect("encoded krpc must decode");
        prop_assert!(krpc_messages_eq(&m, &decoded));
    }
}

/// Project a contact down to the fields that actually travel on the wire
/// (its `Instant` does not).
fn contact_key(c: &Contact) -> (NodeId, std::net::SocketAddr) {
    (c.id, c.addr)
}

fn responses_eq(a: &Response, b: &Response) -> bool {
    match (a, b) {
        (Response::Id { id: x }, Response::Id { id: y }) => x == y,
        (Response::Nodes { id: ix, nodes: nx }, Response::Nodes { id: iy, nodes: ny }) => {
            ix == iy && nx.iter().map(contact_key).eq(ny.iter().map(contact_key))
        }
        (
            Response::Peers {
                id: ix,
                token: tx,
                values: vx,
            },
            Response::Peers {
                id: iy,
                token: ty,
                values: vy,
            },
        ) => ix == iy && tx == ty && vx == vy,
        (
            Response::PeersNodes {
                id: ix,
                token: tx,
                nodes: nx,
            },
            Response::PeersNodes {
                id: iy,
                token: ty,
                nodes: ny,
            },
        ) => ix == iy && tx == ty && nx.iter().map(contact_key).eq(ny.iter().map(contact_key)),
        _ => false,
    }
}

fn krpc_messages_eq(a: &krpc::Message, b: &krpc::Message) -> bool {
    match (a, b) {
        (
            krpc::Message::Query {
                transaction_id: tx,
                query: qx,
            },
            krpc::Message::Query {
                transaction_id: ty,
                query: qy,
            },
        ) => tx == ty && qx == qy,
        (
            krpc::Message::Response {
                transaction_id: tx,
                response: rx,
            },
            krpc::Message::Response {
                transaction_id: ty,
                response: ry,
            },
        ) => tx == ty && responses_eq(rx, ry),
        (
            krpc::Message::Error {
                transaction_id: tx,
                code: cx,
                message: mx,
            },
            krpc::Message::Error {
                transaction_id: ty,
                code: cy,
                message: my,
            },
        ) => tx == ty && cx == cy && mx == my,
        _ => false,
    }
}
