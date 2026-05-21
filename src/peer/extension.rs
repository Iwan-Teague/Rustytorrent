//! BEP 10 extension protocol + BEP 9 ut_metadata.
//!
//! BEP 10 wraps optional extensions behind a single `Extended` (id 20)
//! BitTorrent message. The very first such message — `ext_id == 0` — is
//! a handshake in which both sides advertise a small bencode dict
//! describing which named extensions they support and what numeric IDs
//! they want messages for those extensions to use. There is no
//! requirement that the IDs match across peers; each side tells the
//! other which numeric ID they should use *back at me*. The mapping is
//! per-connection, not global.
//!
//! BEP 9 (ut_metadata) is the magnet-link bootstrap: when we only have
//! the info_hash (from a `magnet:?xt=urn:btih:…` URI), we ask each
//! ext-protocol-capable peer to send us pieces of the info dict, which
//! we re-assemble and hash-verify against the info_hash from the
//! magnet. Without this, magnet links don't work at all.
//!
//! Each ut_metadata message has the structure:
//! ```text
//!   payload = bencode_dict || raw_piece_bytes_if_data
//! ```
//! where `bencode_dict` is one of:
//! - `{msg_type: 0, piece: N}`              — request piece N
//! - `{msg_type: 1, piece: N, total_size: T}` — data response (followed by raw bytes)
//! - `{msg_type: 2, piece: N}`              — reject
//!
//! Metadata is sliced into 16 KiB pieces, identical to the BT block
//! size constant. We always assign id `1` for ut_metadata in our own
//! handshake `m` dict; this is the value peers should use when sending
//! ut_metadata messages to us.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::metainfo::bencode::BencodeValue;

/// Size of each metadata piece, per BEP 9.
pub const METADATA_PIECE_SIZE: usize = 16384;

/// Our assigned extension IDs — these are what peers should use when
/// sending us an extension message. The peer's IDs for the same
/// extensions are negotiated separately in their handshake.
pub const OUR_UT_METADATA_ID: u8 = 1;
/// Our assigned id for incoming BEP 11 (ut_pex) messages.
pub const OUR_UT_PEX_ID: u8 = 2;

/// The well-known ext_id for the extension handshake itself.
pub const EXT_HANDSHAKE_ID: u8 = 0;

/// Build our outgoing extension-handshake payload. The `m` dict tells
/// peers which numeric IDs to use when sending us specific extension
/// messages — we advertise both `ut_metadata` and `ut_pex` so peers
/// know how to address ut_metadata requests (which we silently
/// ignore today — no harm) and ut_pex peer-list updates (which we
/// parse and route to the engine's PeerManager).
///
/// `v` ("client version string") is conventional and helps debugging.
pub fn build_handshake_payload() -> Vec<u8> {
    let mut m_map = BTreeMap::new();
    m_map.insert(
        b"ut_metadata".to_vec(),
        BencodeValue::Int(OUR_UT_METADATA_ID as i64),
    );
    m_map.insert(b"ut_pex".to_vec(), BencodeValue::Int(OUR_UT_PEX_ID as i64));

    let mut root = BTreeMap::new();
    root.insert(b"m".to_vec(), BencodeValue::Dict(m_map));
    root.insert(
        b"v".to_vec(),
        BencodeValue::Bytes(format!("rustytorrent {}", env!("CARGO_PKG_VERSION")).into_bytes()),
    );
    // `reqq` advertises how many outstanding metadata requests we'll
    // accept; we don't serve metadata yet (no info dict to share when
    // bootstrapping via magnet ourselves), so 0 is honest.
    root.insert(b"reqq".to_vec(), BencodeValue::Int(0));
    BencodeValue::Dict(root).to_bytes()
}

/// What we learn about a peer from their extension-handshake payload.
/// All fields are optional — peers may decline to advertise any of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerExtensionInfo {
    /// The numeric ID *they* expect us to use when we send them a
    /// `ut_metadata` extension message. `None` means they didn't list
    /// `ut_metadata` in their `m` dict — they can't serve metadata to
    /// us, so we should drop the connection and try another peer.
    pub their_ut_metadata_id: Option<u8>,
    /// The numeric ID *they* expect us to use when we send them a
    /// `ut_pex` (BEP 11) extension message. `None` → they don't speak
    /// PEX (or don't want to receive it from us); we just don't send.
    pub their_ut_pex_id: Option<u8>,
    /// The size in bytes of their info dict, if they're seeding a
    /// torrent for which they have the metadata. Required for us to
    /// know how many `piece` requests to issue.
    pub metadata_size: Option<u32>,
}

/// Parse the bencoded handshake payload received from a peer.
pub fn parse_handshake_payload(payload: &[u8]) -> Result<PeerExtensionInfo> {
    let root = BencodeValue::parse_all(payload)
        .map_err(|e| Error::Network(format!("ext handshake bencode: {e}")))?;
    let dict = root
        .as_dict()
        .map_err(|_| Error::Network("ext handshake not a dict".into()))?;

    let mut info = PeerExtensionInfo::default();
    if let Some(m) = dict.get(b"m".as_slice()) {
        let m_dict = m
            .as_dict()
            .map_err(|_| Error::Network("ext handshake `m` not a dict".into()))?;
        if let Some(v) = m_dict.get(b"ut_metadata".as_slice()) {
            let id = v
                .as_int()
                .map_err(|_| Error::Network("ut_metadata id not int".into()))?;
            if !(0..=255).contains(&id) {
                return Err(Error::Network(format!("ut_metadata id out of range: {id}")));
            }
            // ID 0 is reserved for the handshake itself; peers MUST NOT
            // assign it. Treat as malformed and skip.
            if id != 0 {
                info.their_ut_metadata_id = Some(id as u8);
            }
        }
        if let Some(v) = m_dict.get(b"ut_pex".as_slice()) {
            let id = v
                .as_int()
                .map_err(|_| Error::Network("ut_pex id not int".into()))?;
            if (1..=255).contains(&id) {
                info.their_ut_pex_id = Some(id as u8);
            }
            // id 0 disables ut_pex per BEP 10; skip without error.
        }
    }
    if let Some(sz) = dict.get(b"metadata_size".as_slice()) {
        let n = sz
            .as_int()
            .map_err(|_| Error::Network("metadata_size not int".into()))?;
        if n <= 0 {
            return Err(Error::Network(format!("metadata_size non-positive: {n}")));
        }
        // Sanity ceiling: 100 MB of metadata is wildly larger than any
        // real torrent's info dict (usually <100 KB). Refuse rather than
        // allocate.
        const MAX_METADATA_SIZE: i64 = 100 * 1024 * 1024;
        if n > MAX_METADATA_SIZE {
            return Err(Error::Network(format!(
                "metadata_size too large: {n} bytes"
            )));
        }
        info.metadata_size = Some(n as u32);
    }
    Ok(info)
}

/// Build the `request` ut_metadata payload for `piece`. Sent to the
/// peer at *their* assigned `ut_metadata` ID (the value carried back in
/// `PeerExtensionInfo::their_ut_metadata_id`).
pub fn build_metadata_request(piece: u32) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"msg_type".to_vec(), BencodeValue::Int(0));
    d.insert(b"piece".to_vec(), BencodeValue::Int(piece as i64));
    BencodeValue::Dict(d).to_bytes()
}

/// Outcome of decoding a ut_metadata payload received from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataResponse {
    /// Peer is sending us piece `piece`. `total_size` is the full
    /// metadata length, which the peer re-asserts in every data response
    /// (handy as a cross-check). `data` is the raw piece bytes.
    Data {
        piece: u32,
        total_size: u32,
        data: Vec<u8>,
    },
    /// Peer is rejecting our request for `piece` — typically because
    /// they don't have the metadata themselves. Try another peer.
    Reject { piece: u32 },
    /// Peer sent us a request (we ignore — we never seed metadata in
    /// the bootstrap path) or some other ut_metadata message type we
    /// don't care about right now.
    Other,
}

/// Parse a ut_metadata extension payload. The wire format is a bencoded
/// dict followed (only for `msg_type == 1`) by the raw piece bytes
/// concatenated in the same Extended message envelope.
pub fn parse_metadata_response(payload: &[u8]) -> Result<MetadataResponse> {
    let (dict, rest) = BencodeValue::parse(payload)
        .map_err(|e| Error::Network(format!("ut_metadata bencode: {e}")))?;
    let d = dict
        .as_dict()
        .map_err(|_| Error::Network("ut_metadata not a dict".into()))?;
    let msg_type = d
        .get(b"msg_type".as_slice())
        .ok_or_else(|| Error::Network("ut_metadata missing msg_type".into()))?
        .as_int()
        .map_err(|_| Error::Network("ut_metadata msg_type not int".into()))?;
    let piece = d
        .get(b"piece".as_slice())
        .ok_or_else(|| Error::Network("ut_metadata missing piece".into()))?
        .as_int()
        .map_err(|_| Error::Network("ut_metadata piece not int".into()))?;
    if piece < 0 || piece > u32::MAX as i64 {
        return Err(Error::Network(format!("ut_metadata piece OOR: {piece}")));
    }
    let piece = piece as u32;

    match msg_type {
        0 => Ok(MetadataResponse::Other), // peer requesting from us; ignored
        1 => {
            let total_size = d
                .get(b"total_size".as_slice())
                .ok_or_else(|| Error::Network("ut_metadata data missing total_size".into()))?
                .as_int()
                .map_err(|_| Error::Network("ut_metadata total_size not int".into()))?;
            if total_size <= 0 || total_size > 100 * 1024 * 1024 {
                return Err(Error::Network(format!(
                    "ut_metadata total_size implausible: {total_size}"
                )));
            }
            Ok(MetadataResponse::Data {
                piece,
                total_size: total_size as u32,
                data: rest.to_vec(),
            })
        }
        2 => Ok(MetadataResponse::Reject { piece }),
        other => {
            tracing::debug!(target: "ext", msg_type = other, "unknown ut_metadata msg_type");
            Ok(MetadataResponse::Other)
        }
    }
}

/// BEP 11 recommends capping each ut_pex message to ~50 added entries
/// per direction to keep payload size sane and avoid flooding peers.
pub const PEX_MAX_ENTRIES_PER_DIRECTION: usize = 50;

/// Build an outgoing ut_pex payload covering the `added` and `dropped`
/// peer sets. IPv4 and IPv6 entries are split into the spec-required
/// `added`/`added6` (and `dropped`/`dropped6`) fields. Flags bytes are
/// all-zero today — we don't yet advertise per-peer encryption or
/// seed-status hints in the PEX channel.
///
/// Empty `added` AND empty `dropped` still produces a valid (but
/// useless) payload — the caller should skip the send in that case.
pub fn build_pex_payload(
    added: &[std::net::SocketAddr],
    dropped: &[std::net::SocketAddr],
) -> Vec<u8> {
    let (added4, added6) = split_v4_v6(added);
    let (dropped4, dropped6) = split_v4_v6(dropped);

    let mut d = BTreeMap::new();

    if !added4.is_empty() {
        d.insert(
            b"added".to_vec(),
            BencodeValue::Bytes(encode_compact_v4(&added4)),
        );
        d.insert(
            b"added.f".to_vec(),
            BencodeValue::Bytes(vec![0u8; added4.len()]),
        );
    }
    if !added6.is_empty() {
        d.insert(
            b"added6".to_vec(),
            BencodeValue::Bytes(encode_compact_v6(&added6)),
        );
        d.insert(
            b"added6.f".to_vec(),
            BencodeValue::Bytes(vec![0u8; added6.len()]),
        );
    }
    if !dropped4.is_empty() {
        d.insert(
            b"dropped".to_vec(),
            BencodeValue::Bytes(encode_compact_v4(&dropped4)),
        );
    }
    if !dropped6.is_empty() {
        d.insert(
            b"dropped6".to_vec(),
            BencodeValue::Bytes(encode_compact_v6(&dropped6)),
        );
    }

    BencodeValue::Dict(d).to_bytes()
}

fn split_v4_v6(
    addrs: &[std::net::SocketAddr],
) -> (Vec<std::net::SocketAddrV4>, Vec<std::net::SocketAddrV6>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for a in addrs {
        match a {
            std::net::SocketAddr::V4(a4) => v4.push(*a4),
            std::net::SocketAddr::V6(a6) => v6.push(*a6),
        }
    }
    (v4, v6)
}

fn encode_compact_v4(addrs: &[std::net::SocketAddrV4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addrs.len() * 6);
    for a in addrs {
        out.extend_from_slice(&a.ip().octets());
        out.extend_from_slice(&a.port().to_be_bytes());
    }
    out
}

fn encode_compact_v6(addrs: &[std::net::SocketAddrV6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addrs.len() * 18);
    for a in addrs {
        out.extend_from_slice(&a.ip().octets());
        out.extend_from_slice(&a.port().to_be_bytes());
    }
    out
}

/// BEP 11 ut_pex payload parsed out of an incoming Extended message.
/// We only need the `added` peer list — the dropped list is for clients
/// that want to maintain a view of "still alive in this swarm"
/// per-source, which we don't bother tracking. IPv4 ("added") and IPv6
/// ("added6") families are both returned, deduplicated by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PexMessage {
    pub added: Vec<std::net::SocketAddr>,
}

/// Parse a ut_pex extension payload. Malformed entries are skipped
/// rather than fatal — peers vary in how strict they are about packing
/// the compact-peer lists.
pub fn parse_pex(payload: &[u8]) -> Result<PexMessage> {
    let v = BencodeValue::parse_all(payload)
        .map_err(|e| Error::Network(format!("ut_pex bencode: {e}")))?;
    let d = v
        .as_dict()
        .map_err(|_| Error::Network("ut_pex not a dict".into()))?;

    let mut added: Vec<std::net::SocketAddr> = Vec::new();
    // IPv4: 6-byte entries (4 addr + 2 port BE).
    if let Some(BencodeValue::Bytes(bytes)) = d.get(b"added".as_slice()) {
        for chunk in bytes.chunks_exact(6) {
            let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
            let port = u16::from_be_bytes([chunk[4], chunk[5]]);
            if port == 0 {
                continue; // 0 means "no listen socket"; can't dial it
            }
            added.push(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
        }
    }
    // IPv6: 18-byte entries (16 addr + 2 port BE).
    if let Some(BencodeValue::Bytes(bytes)) = d.get(b"added6".as_slice()) {
        for chunk in bytes.chunks_exact(18) {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&chunk[..16]);
            let ip = std::net::Ipv6Addr::from(addr);
            let port = u16::from_be_bytes([chunk[16], chunk[17]]);
            if port == 0 {
                continue;
            }
            added.push(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port));
        }
    }
    Ok(PexMessage { added })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_payload_is_parseable_and_lists_ut_metadata() {
        let bytes = build_handshake_payload();
        // Round-trip: peer-side parse of our payload should see our ID.
        let info = parse_handshake_payload(&bytes).unwrap();
        // Our advertised m dict has ut_metadata, so a peer parsing
        // OUR bytes sees our assigned id as "their_ut_metadata_id".
        assert_eq!(info.their_ut_metadata_id, Some(OUR_UT_METADATA_ID));
        assert!(
            info.metadata_size.is_none(),
            "we don't advertise a metadata_size since we have none to share"
        );
    }

    #[test]
    fn parse_handshake_extracts_metadata_size() {
        // Hand-build a peer payload: { m: { ut_metadata: 3 }, metadata_size: 1234 }
        let mut m = BTreeMap::new();
        m.insert(b"ut_metadata".to_vec(), BencodeValue::Int(3));
        let mut d = BTreeMap::new();
        d.insert(b"m".to_vec(), BencodeValue::Dict(m));
        d.insert(b"metadata_size".to_vec(), BencodeValue::Int(1234));
        let bytes = BencodeValue::Dict(d).to_bytes();
        let info = parse_handshake_payload(&bytes).unwrap();
        assert_eq!(info.their_ut_metadata_id, Some(3));
        assert_eq!(info.metadata_size, Some(1234));
    }

    #[test]
    fn parse_handshake_handles_missing_metadata_keys() {
        // Peer without ut_metadata in `m` — can't serve metadata.
        let mut d = BTreeMap::new();
        let m = BTreeMap::new();
        d.insert(b"m".to_vec(), BencodeValue::Dict(m));
        let bytes = BencodeValue::Dict(d).to_bytes();
        let info = parse_handshake_payload(&bytes).unwrap();
        assert!(info.their_ut_metadata_id.is_none());
        assert!(info.metadata_size.is_none());
    }

    #[test]
    fn parse_handshake_rejects_oversized_metadata() {
        let mut m = BTreeMap::new();
        m.insert(b"ut_metadata".to_vec(), BencodeValue::Int(1));
        let mut d = BTreeMap::new();
        d.insert(b"m".to_vec(), BencodeValue::Dict(m));
        // 200 MB > our 100 MB cap.
        d.insert(
            b"metadata_size".to_vec(),
            BencodeValue::Int(200 * 1024 * 1024),
        );
        let bytes = BencodeValue::Dict(d).to_bytes();
        assert!(parse_handshake_payload(&bytes).is_err());
    }

    #[test]
    fn build_metadata_request_is_a_well_formed_dict() {
        let bytes = build_metadata_request(7);
        let v = BencodeValue::parse_all(&bytes).unwrap();
        let d = v.as_dict().unwrap();
        assert_eq!(d.get(b"msg_type".as_slice()).unwrap().as_int().unwrap(), 0);
        assert_eq!(d.get(b"piece".as_slice()).unwrap().as_int().unwrap(), 7);
    }

    #[test]
    fn parse_metadata_data_response_separates_dict_and_payload() {
        // Build a data response: dict + trailing raw bytes.
        let mut d = BTreeMap::new();
        d.insert(b"msg_type".to_vec(), BencodeValue::Int(1));
        d.insert(b"piece".to_vec(), BencodeValue::Int(0));
        d.insert(b"total_size".to_vec(), BencodeValue::Int(1234));
        let mut bytes = BencodeValue::Dict(d).to_bytes();
        let payload_bytes: Vec<u8> = (0..16u8).collect();
        bytes.extend_from_slice(&payload_bytes);

        match parse_metadata_response(&bytes).unwrap() {
            MetadataResponse::Data {
                piece,
                total_size,
                data,
            } => {
                assert_eq!(piece, 0);
                assert_eq!(total_size, 1234);
                assert_eq!(data, payload_bytes);
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn parse_metadata_reject() {
        let mut d = BTreeMap::new();
        d.insert(b"msg_type".to_vec(), BencodeValue::Int(2));
        d.insert(b"piece".to_vec(), BencodeValue::Int(5));
        let bytes = BencodeValue::Dict(d).to_bytes();
        assert_eq!(
            parse_metadata_response(&bytes).unwrap(),
            MetadataResponse::Reject { piece: 5 }
        );
    }

    #[test]
    fn handshake_payload_advertises_ut_pex_too() {
        let bytes = build_handshake_payload();
        let v = BencodeValue::parse_all(&bytes).unwrap();
        let m = v.dict_get(b"m").unwrap().as_dict().unwrap();
        assert_eq!(
            m.get(b"ut_pex".as_slice()).unwrap().as_int().unwrap(),
            OUR_UT_PEX_ID as i64
        );
    }

    #[test]
    fn parse_pex_added_ipv4() {
        // Two compact peers: 1.2.3.4:5678 and 9.10.11.12:80
        let mut payload = Vec::new();
        payload.extend_from_slice(&[1, 2, 3, 4]);
        payload.extend_from_slice(&5678u16.to_be_bytes());
        payload.extend_from_slice(&[9, 10, 11, 12]);
        payload.extend_from_slice(&80u16.to_be_bytes());

        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), BencodeValue::Bytes(payload));
        let bytes = BencodeValue::Dict(d).to_bytes();

        let pex = parse_pex(&bytes).unwrap();
        assert_eq!(pex.added.len(), 2);
        assert_eq!(
            pex.added[0],
            "1.2.3.4:5678".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            pex.added[1],
            "9.10.11.12:80".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_pex_skips_zero_port_entries() {
        // 1.2.3.4:0 — port 0 means "no listen socket"; drop it.
        let mut payload = Vec::new();
        payload.extend_from_slice(&[1, 2, 3, 4, 0, 0]);
        let mut d = BTreeMap::new();
        d.insert(b"added".to_vec(), BencodeValue::Bytes(payload));
        let bytes = BencodeValue::Dict(d).to_bytes();
        let pex = parse_pex(&bytes).unwrap();
        assert!(pex.added.is_empty());
    }

    #[test]
    fn parse_pex_handles_missing_keys() {
        // Empty dict — no `added` field at all.
        let d: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
        let bytes = BencodeValue::Dict(d).to_bytes();
        let pex = parse_pex(&bytes).unwrap();
        assert!(pex.added.is_empty());
    }

    #[test]
    fn build_pex_payload_is_parseable_round_trip() {
        let added: Vec<std::net::SocketAddr> = vec![
            "1.2.3.4:5678".parse().unwrap(),
            "[::1]:6881".parse().unwrap(),
        ];
        let dropped: Vec<std::net::SocketAddr> = vec!["9.9.9.9:80".parse().unwrap()];
        let bytes = build_pex_payload(&added, &dropped);
        // Round-trip through parse_pex: only `added`/`added6` are
        // checked; dropped goes into separate keys we don't surface
        // in PexMessage today.
        let pex = parse_pex(&bytes).unwrap();
        assert_eq!(pex.added.len(), 2);
        assert!(pex.added.contains(&"1.2.3.4:5678".parse().unwrap()));
        assert!(pex.added.contains(&"[::1]:6881".parse().unwrap()));
    }

    #[test]
    fn build_pex_payload_empty_added_and_dropped_yields_empty_dict() {
        let bytes = build_pex_payload(&[], &[]);
        // Empty dict bencodes as "de" (start dict, end dict).
        assert_eq!(bytes, b"de");
    }

    #[test]
    fn parse_pex_ipv6_added6() {
        // One IPv6 peer: ::1:6881
        let mut payload = Vec::new();
        let ip = std::net::Ipv6Addr::LOCALHOST.octets();
        payload.extend_from_slice(&ip);
        payload.extend_from_slice(&6881u16.to_be_bytes());

        let mut d = BTreeMap::new();
        d.insert(b"added6".to_vec(), BencodeValue::Bytes(payload));
        let bytes = BencodeValue::Dict(d).to_bytes();

        let pex = parse_pex(&bytes).unwrap();
        assert_eq!(pex.added.len(), 1);
        assert_eq!(
            pex.added[0],
            "[::1]:6881".parse::<std::net::SocketAddr>().unwrap()
        );
    }
}
