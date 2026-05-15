use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::peer_id::PeerId;

pub const PSTR: &[u8; 19] = b"BitTorrent protocol";
pub const PSTRLEN: u8 = 19;
pub const HANDSHAKE_LEN: usize = 1 + 19 + 8 + 20 + 20; // 68 bytes

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: PeerId,
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: PeerId) -> Self {
        // No reserved bits set by default — extensions enabled per-feature.
        Self {
            reserved: [0u8; 8],
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
        if theirs.info_hash != info_hash {
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
        if theirs.info_hash != info_hash {
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
