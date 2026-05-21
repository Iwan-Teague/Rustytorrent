use std::sync::OnceLock;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::peer_id::PeerId;

pub const PSTR: &[u8; 19] = b"BitTorrent protocol";
pub const PSTRLEN: u8 = 19;
pub const HANDSHAKE_LEN: usize = 1 + 19 + 8 + 20 + 20; // 68 bytes

/// Reserved bits the local engine wants to advertise on every handshake.
/// Set once at engine startup from the runtime config (DHT enabled, etc.);
/// before that, every handshake goes out as all-zero (the conservative
/// "I support nothing" pattern).
///
/// B5 — fingerprint reduction: we advertise the bits we actually support
/// rather than always emitting `[0; 8]`. The latter is itself a recognisable
/// fingerprint (modern clients almost universally set the DHT bit + the
/// BEP 10 extension-protocol bit), so the right move is to set the bits
/// our feature set really implements. We only set DHT today; the extension
/// protocol bit will join when BEP 10 lands.
static EXTENSION_BYTES: OnceLock<[u8; 8]> = OnceLock::new();

/// BEP 5 (DHT) advertises support via byte 7 bit 0 — value `0x01`.
const RESERVED_BIT_DHT: u8 = 0x01;
/// BEP 10 (extension protocol) advertises support via byte 5 bit 4 —
/// value `0x10`. Setting this opts us into receiving `Extended` (id 20)
/// messages and into the magnet-link / ut_metadata flow.
const RESERVED_BIT_EXTENSION: u8 = 0x10;

/// Install the reserved-bytes pattern for the rest of the process. Idempotent
/// (first call wins); the engine calls this once during `run()`. Subsequent
/// callers see the original value — fine, since the engine is the single
/// owner of this decision.
pub fn set_extension_bytes(bytes: [u8; 8]) {
    let _ = EXTENSION_BYTES.set(bytes);
}

/// Build the reserved-bytes byte string from a flag set. Kept separate from
/// `set_extension_bytes` so tests can exercise the bit layout without
/// touching the global.
///
/// `extension_protocol` is always advertised once the BEP 10 implementation
/// landed — it's how peers know we can speak `ut_metadata` (BEP 9) for
/// magnet-link bootstrap. DHT is conditional on the runtime flag.
pub fn extension_bytes_from(dht_enabled: bool, extension_protocol: bool) -> [u8; 8] {
    let mut r = [0u8; 8];
    if dht_enabled {
        r[7] |= RESERVED_BIT_DHT;
    }
    if extension_protocol {
        r[5] |= RESERVED_BIT_EXTENSION;
    }
    r
}

/// True iff the peer advertised the BEP 10 extension-protocol reserved bit.
pub fn supports_extension_protocol(reserved: &[u8; 8]) -> bool {
    reserved[5] & RESERVED_BIT_EXTENSION != 0
}

fn current_extension_bytes() -> [u8; 8] {
    EXTENSION_BYTES.get().copied().unwrap_or([0u8; 8])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: PeerId,
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: PeerId) -> Self {
        // Reserved-byte pattern comes from the once-set engine config so
        // every handshake (outgoing AND incoming, plain AND MSE) advertises
        // the same capability set.
        Self {
            reserved: current_extension_bytes(),
            info_hash,
            peer_id,
        }
    }

    pub fn encode(&self) -> [u8; HANDSHAKE_LEN] {
        let mut buf = [0u8; HANDSHAKE_LEN];
        buf[0] = PSTRLEN;
        buf[1..20].copy_from_slice(PSTR);
        buf[20..28].copy_from_slice(&self.reserved);
        buf[28..48].copy_from_slice(&self.info_hash);
        buf[48..68].copy_from_slice(&self.peer_id);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HANDSHAKE_LEN {
            return Err(Error::Handshake(format!(
                "handshake too short: {}",
                buf.len()
            )));
        }
        if buf[0] != PSTRLEN {
            return Err(Error::Handshake(format!(
                "bad pstrlen: {} (expected {})",
                buf[0], PSTRLEN
            )));
        }
        if &buf[1..20] != PSTR.as_slice() {
            return Err(Error::Handshake("bad protocol string".into()));
        }
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[20..28]);
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[28..48]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[48..68]);
        Ok(Self {
            reserved,
            info_hash,
            peer_id,
        })
    }

    /// Perform the outgoing handshake: send ours, read theirs, verify info_hash.
    pub async fn perform_outgoing<S>(
        stream: &mut S,
        info_hash: [u8; 20],
        peer_id: PeerId,
    ) -> Result<Handshake>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ours = Handshake::new(info_hash, peer_id);
        let encoded = ours.encode();
        stream
            .write_all(&encoded)
            .await
            .map_err(|e| Error::Handshake(format!("write: {e}")))?;

        let mut buf = [0u8; HANDSHAKE_LEN];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Handshake(format!("read: {e}")))?;
        let theirs = Handshake::decode(&buf)?;
        if !bool::from(theirs.info_hash.ct_eq(&info_hash)) {
            return Err(Error::Handshake("info_hash mismatch".into()));
        }
        Ok(theirs)
    }

    /// Perform the incoming handshake: read theirs, verify info_hash, send ours.
    pub async fn perform_incoming<S>(
        stream: &mut S,
        info_hash: [u8; 20],
        peer_id: PeerId,
    ) -> Result<Handshake>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = [0u8; HANDSHAKE_LEN];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Handshake(format!("read: {e}")))?;
        let theirs = Handshake::decode(&buf)?;
        if !bool::from(theirs.info_hash.ct_eq(&info_hash)) {
            return Err(Error::Handshake("info_hash mismatch".into()));
        }
        let ours = Handshake::new(info_hash, peer_id);
        stream
            .write_all(&ours.encode())
            .await
            .map_err(|e| Error::Handshake(format!("write: {e}")))?;
        Ok(theirs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let h = Handshake::new([0xAA; 20], [0xBB; 20]);
        let buf = h.encode();
        assert_eq!(buf.len(), 68);
        assert_eq!(buf[0], 19);
        assert_eq!(&buf[1..20], b"BitTorrent protocol");
        let decoded = Handshake::decode(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn extension_bytes_all_off_is_all_zero() {
        assert_eq!(extension_bytes_from(false, false), [0u8; 8]);
    }

    #[test]
    fn extension_bytes_dht_on_sets_last_byte_bit_zero() {
        let bytes = extension_bytes_from(true, false);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[6], 0);
        assert_eq!(
            bytes[7] & 0x01,
            0x01,
            "DHT bit (byte 7, value 0x01) must be set"
        );
    }

    #[test]
    fn extension_bytes_extension_protocol_sets_byte_5_bit_4() {
        let bytes = extension_bytes_from(false, true);
        assert_eq!(bytes[5] & 0x10, 0x10, "BEP 10 bit (byte 5, value 0x10)");
        assert_eq!(bytes[7], 0);
    }

    #[test]
    fn supports_extension_protocol_detects_the_bit() {
        let yes = extension_bytes_from(false, true);
        let no = extension_bytes_from(false, false);
        assert!(supports_extension_protocol(&yes));
        assert!(!supports_extension_protocol(&no));
    }

    #[test]
    fn decode_rejects_bad_pstrlen() {
        let mut buf = [0u8; 68];
        buf[0] = 18;
        assert!(Handshake::decode(&buf).is_err());
    }

    #[test]
    fn decode_rejects_bad_pstr() {
        let mut buf = [0u8; 68];
        buf[0] = 19;
        buf[1..20].copy_from_slice(b"BadTorrent protocol");
        assert!(Handshake::decode(&buf).is_err());
    }

    #[test]
    fn decode_rejects_short() {
        assert!(Handshake::decode(&[0u8; 32]).is_err());
    }

    #[tokio::test]
    async fn outgoing_handshake_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(128);
        let info_hash = [0x11u8; 20];
        let our_peer_id = [0x22u8; 20];
        let their_peer_id = [0x33u8; 20];

        let server = tokio::spawn(async move {
            Handshake::perform_incoming(&mut b, info_hash, their_peer_id)
                .await
                .unwrap()
        });

        let theirs = Handshake::perform_outgoing(&mut a, info_hash, our_peer_id)
            .await
            .unwrap();
        let theirs_from_server = server.await.unwrap();
        assert_eq!(theirs.info_hash, info_hash);
        assert_eq!(theirs.peer_id, their_peer_id);
        assert_eq!(theirs_from_server.peer_id, our_peer_id);
    }
}
