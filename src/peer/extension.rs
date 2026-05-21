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

/// The well-known ext_id for the extension handshake itself.
pub const EXT_HANDSHAKE_ID: u8 = 0;

/// Build our outgoing extension-handshake payload. The single field that
/// matters today is `m.ut_metadata` — telling peers which numeric ID to
/// use when shipping us `ut_metadata` messages. `v` ("client version
/// string") is conventional and helps debugging.
pub fn build_handshake_payload() -> Vec<u8> {
    let mut m_map = BTreeMap::new();
    m_map.insert(
        b"ut_metadata".to_vec(),
        BencodeValue::Int(OUR_UT_METADATA_ID as i64),
    );

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
/// Both fields are optional — peers may decline to advertise either.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerExtensionInfo {
    /// The numeric ID *they* expect us to use when we send them a
    /// `ut_metadata` extension message. `None` means they didn't list
    /// `ut_metadata` in their `m` dict — they can't serve metadata to
    /// us, so we should drop the connection and try another peer.
    pub their_ut_metadata_id: Option<u8>,
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
}
