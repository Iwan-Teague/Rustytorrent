use bitvec::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

pub const BLOCK_SIZE: u32 = 16384; // 16 KiB — fixed per BEP 3 convention.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    /// BEP 10 extension protocol envelope. `ext_id == 0` is the handshake;
    /// other values are per-peer-negotiated IDs from the peer's `m` dict.
    /// The `payload` is whatever the extension specifies (typically a
    /// bencoded dict for ut_metadata / ut_pex / etc).
    Extended {
        ext_id: u8,
        payload: Vec<u8>,
    },
}

impl Message {
    pub const ID_CHOKE: u8 = 0;
    pub const ID_UNCHOKE: u8 = 1;
    pub const ID_INTERESTED: u8 = 2;
    pub const ID_NOT_INTERESTED: u8 = 3;
    pub const ID_HAVE: u8 = 4;
    pub const ID_BITFIELD: u8 = 5;
    pub const ID_REQUEST: u8 = 6;
    pub const ID_PIECE: u8 = 7;
    pub const ID_CANCEL: u8 = 8;
    /// BEP 10 — extension protocol envelope.
    pub const ID_EXTENDED: u8 = 20;

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::KeepAlive => 0u32.to_be_bytes().to_vec(),
            Message::Choke => Self::tag(Self::ID_CHOKE, &[]),
            Message::Unchoke => Self::tag(Self::ID_UNCHOKE, &[]),
            Message::Interested => Self::tag(Self::ID_INTERESTED, &[]),
            Message::NotInterested => Self::tag(Self::ID_NOT_INTERESTED, &[]),
            Message::Have(i) => Self::tag(Self::ID_HAVE, &i.to_be_bytes()),
            Message::Bitfield(b) => Self::tag(Self::ID_BITFIELD, b),
            Message::Request {
                index,
                begin,
                length,
            } => {
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&index.to_be_bytes());
                p.extend_from_slice(&begin.to_be_bytes());
                p.extend_from_slice(&length.to_be_bytes());
                Self::tag(Self::ID_REQUEST, &p)
            }
            Message::Piece { index, begin, data } => {
                let mut p = Vec::with_capacity(8 + data.len());
                p.extend_from_slice(&index.to_be_bytes());
                p.extend_from_slice(&begin.to_be_bytes());
                p.extend_from_slice(data);
                Self::tag(Self::ID_PIECE, &p)
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&index.to_be_bytes());
                p.extend_from_slice(&begin.to_be_bytes());
                p.extend_from_slice(&length.to_be_bytes());
                Self::tag(Self::ID_CANCEL, &p)
            }
            Message::Extended { ext_id, payload } => {
                let mut p = Vec::with_capacity(1 + payload.len());
                p.push(*ext_id);
                p.extend_from_slice(payload);
                Self::tag(Self::ID_EXTENDED, &p)
            }
        }
    }

    fn tag(id: u8, payload: &[u8]) -> Vec<u8> {
        let len = (1 + payload.len()) as u32;
        let mut out = Vec::with_capacity(4 + 1 + payload.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(id);
        out.extend_from_slice(payload);
        out
    }

    /// Decode a wire frame from `frame` bytes (payload-only — `[id][payload…]`,
    /// not including the 4-byte length prefix). A zero-length frame is a keep-alive
    /// and should be constructed by the caller before this is invoked.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        if frame.is_empty() {
            return Ok(Message::KeepAlive);
        }
        let id = frame[0];
        let p = &frame[1..];
        match id {
            Self::ID_CHOKE => ensure_empty(p).map(|_| Message::Choke),
            Self::ID_UNCHOKE => ensure_empty(p).map(|_| Message::Unchoke),
            Self::ID_INTERESTED => ensure_empty(p).map(|_| Message::Interested),
            Self::ID_NOT_INTERESTED => ensure_empty(p).map(|_| Message::NotInterested),
            Self::ID_HAVE => {
                if p.len() != 4 {
                    return Err(Error::Network(format!("have payload {} != 4", p.len())));
                }
                Ok(Message::Have(u32::from_be_bytes([p[0], p[1], p[2], p[3]])))
            }
            Self::ID_BITFIELD => Ok(Message::Bitfield(p.to_vec())),
            Self::ID_REQUEST => Self::decode_index_begin_length(p, Message::ID_REQUEST),
            Self::ID_PIECE => {
                if p.len() < 8 {
                    return Err(Error::Network(format!("piece short: {}", p.len())));
                }
                let index = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                let begin = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
                let data = p[8..].to_vec();
                Ok(Message::Piece { index, begin, data })
            }
            Self::ID_CANCEL => Self::decode_index_begin_length(p, Message::ID_CANCEL),
            Self::ID_EXTENDED => {
                if p.is_empty() {
                    return Err(Error::Network("extended payload empty".into()));
                }
                Ok(Message::Extended {
                    ext_id: p[0],
                    payload: p[1..].to_vec(),
                })
            }
            other => Err(Error::Network(format!("unknown message id {other}"))),
        }
    }

    fn decode_index_begin_length(p: &[u8], _id: u8) -> Result<Self> {
        if p.len() != 12 {
            return Err(Error::Network(format!(
                "request/cancel payload {}",
                p.len()
            )));
        }
        let index = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        let begin = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let length = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
        if _id == Message::ID_CANCEL {
            Ok(Message::Cancel {
                index,
                begin,
                length,
            })
        } else {
            Ok(Message::Request {
                index,
                begin,
                length,
            })
        }
    }
}

fn ensure_empty(p: &[u8]) -> Result<()> {
    if !p.is_empty() {
        Err(Error::Network(format!(
            "expected empty payload, got {} bytes",
            p.len()
        )))
    } else {
        Ok(())
    }
}

/// Read one length-prefixed wire frame. Returns the payload (id + body),
/// or an empty Vec for keep-alives.
pub async fn read_frame<R>(reader: &mut R, max_len: u32) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Network(format!("frame len: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > max_len {
        return Err(Error::Network(format!("frame too large: {len}")));
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Network(format!("frame body: {e}")))?;
    Ok(buf)
}

/// Write a single wire frame. `payload` is `[id][body…]` or empty for keep-alive.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    writer
        .write_all(&buf)
        .await
        .map_err(|e| Error::Network(format!("frame write: {e}")))
}

/// Convenience: encode a Message and write it as a frame.
pub async fn write_message<W>(writer: &mut W, msg: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = msg.encode();
    // Message::encode includes the length prefix already.
    writer
        .write_all(&encoded)
        .await
        .map_err(|e| Error::Network(format!("frame write: {e}")))
}

/// Convert a `bitvec` bitfield (Msb0) to a raw byte vector for the wire.
pub fn bitfield_to_bytes(bf: &BitSlice<u8, Msb0>) -> Vec<u8> {
    let mut bytes = vec![0u8; bf.len().div_ceil(8)];
    for (i, bit) in bf.iter().enumerate() {
        if *bit {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    bytes
}

/// Decode a raw wire bitfield into a `BitVec` of exactly `num_pieces` bits.
/// Spare bits at the end must be zero per BEP 3.
pub fn bitfield_from_bytes(bytes: &[u8], num_pieces: usize) -> Result<BitVec<u8, Msb0>> {
    let expected_bytes = num_pieces.div_ceil(8);
    if bytes.len() != expected_bytes {
        return Err(Error::Network(format!(
            "bitfield {} bytes, expected {}",
            bytes.len(),
            expected_bytes
        )));
    }
    let mut out: BitVec<u8, Msb0> = BitVec::repeat(false, num_pieces);
    for i in 0..num_pieces {
        let bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
        out.set(i, bit == 1);
    }
    // Verify spare bits are zero. BEP 3: spare bits past piece count MUST be zero.
    let extra_bits = expected_bytes * 8 - num_pieces;
    if extra_bits > 0 {
        let last = bytes[expected_bytes - 1];
        let mask = (1u8 << extra_bits) - 1;
        if last & mask != 0 {
            return Err(Error::Network("bitfield spare bits not zero".into()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: Message) {
        let bytes = m.encode();
        // strip 4-byte length prefix
        let payload = &bytes[4..];
        let decoded = Message::decode(payload).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn keep_alive_encodes_as_zero_len() {
        assert_eq!(Message::KeepAlive.encode(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn empty_messages_roundtrip() {
        roundtrip(Message::Choke);
        roundtrip(Message::Unchoke);
        roundtrip(Message::Interested);
        roundtrip(Message::NotInterested);
    }

    #[test]
    fn have_roundtrip() {
        roundtrip(Message::Have(12345));
    }

    #[test]
    fn bitfield_roundtrip() {
        roundtrip(Message::Bitfield(vec![0xAB, 0xCD]));
    }

    #[test]
    fn request_roundtrip() {
        roundtrip(Message::Request {
            index: 7,
            begin: 16384,
            length: 16384,
        });
    }

    #[test]
    fn piece_roundtrip() {
        roundtrip(Message::Piece {
            index: 0,
            begin: 0,
            data: vec![1, 2, 3, 4, 5],
        });
    }

    #[test]
    fn cancel_roundtrip() {
        roundtrip(Message::Cancel {
            index: 9,
            begin: 32768,
            length: 16384,
        });
    }

    #[test]
    fn extended_roundtrip() {
        roundtrip(Message::Extended {
            ext_id: 0,
            payload: b"d1:md11:ut_metadatai2eee".to_vec(),
        });
    }

    #[test]
    fn extended_rejects_empty_payload() {
        // Frame body is just [ID_EXTENDED] with no ext_id byte — must error.
        assert!(Message::decode(&[Message::ID_EXTENDED]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_id() {
        assert!(Message::decode(&[99]).is_err());
    }

    #[test]
    fn decode_rejects_bad_have_payload() {
        assert!(Message::decode(&[Message::ID_HAVE, 0, 0]).is_err());
    }

    #[test]
    fn have_encoding_layout() {
        let bytes = Message::Have(7).encode();
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[..4], &5u32.to_be_bytes()); // length = 5
        assert_eq!(bytes[4], Message::ID_HAVE);
        assert_eq!(&bytes[5..], &7u32.to_be_bytes());
    }

    #[test]
    fn request_encoding_layout() {
        let m = Message::Request {
            index: 0x0102_0304,
            begin: 0x0506_0708,
            length: 0x090A_0B0C,
        };
        let bytes = m.encode();
        assert_eq!(&bytes[..4], &13u32.to_be_bytes()); // length = 13
        assert_eq!(bytes[4], Message::ID_REQUEST);
        assert_eq!(&bytes[5..9], &[1, 2, 3, 4]);
        assert_eq!(&bytes[9..13], &[5, 6, 7, 8]);
        assert_eq!(&bytes[13..17], &[9, 10, 11, 12]);
    }

    #[test]
    fn bitfield_bits_roundtrip() {
        let mut bv: BitVec<u8, Msb0> = BitVec::repeat(false, 13);
        bv.set(0, true);
        bv.set(7, true);
        bv.set(12, true);
        let bytes = bitfield_to_bytes(&bv);
        assert_eq!(bytes, vec![0b1000_0001, 0b0000_1000]);
        let restored = bitfield_from_bytes(&bytes, 13).unwrap();
        assert_eq!(restored, bv);
    }

    #[test]
    fn bitfield_rejects_nonzero_spare_bits() {
        // 9 pieces, 2 bytes, last byte 0b1000_0000 → bit 8 set, bit 9..16 nonzero spare
        let bytes = vec![0xFF, 0b1100_0000]; // bit 8 set, bit 9 set, bit 9 is spare for 9 pieces
        assert!(bitfield_from_bytes(&bytes, 9).is_err());
    }

    #[test]
    fn bitfield_rejects_wrong_byte_count() {
        assert!(bitfield_from_bytes(&[0u8; 3], 9).is_err());
    }

    #[tokio::test]
    async fn read_write_frame_roundtrip() {
        let m = Message::Request {
            index: 1,
            begin: 0,
            length: BLOCK_SIZE,
        };
        let (mut a, mut b) = tokio::io::duplex(64);
        let bytes = m.encode();
        write_frame(&mut a, &bytes[4..]).await.unwrap();
        let frame = read_frame(&mut b, 1 << 20).await.unwrap();
        let decoded = Message::decode(&frame).unwrap();
        assert_eq!(decoded, m);
    }

    #[tokio::test]
    async fn read_keepalive() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, &[]).await.unwrap();
        let frame = read_frame(&mut b, 1024).await.unwrap();
        assert!(frame.is_empty());
        assert_eq!(Message::decode(&frame).unwrap(), Message::KeepAlive);
    }
}
