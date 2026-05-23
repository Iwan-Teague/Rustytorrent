//! µTP packet codec — BEP 29 wire format.
//!
//! Wire layout (big-endian, 20 bytes fixed + extensions + payload):
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-------+-------+---------------+-------------------------------+
//! | type  | ver   | extension     | connection_id                 |
//! +-------+-------+---------------+-------------------------------+
//! | timestamp_microseconds                                        |
//! +-------------------------------+-------------------------------+
//! | timestamp_difference_microseconds                             |
//! +-------------------------------+-------------------------------+
//! | wnd_size                                                      |
//! +-------------------------------+-------------------------------+
//! | seq_nr                        | ack_nr                        |
//! +-------------------------------+-------------------------------+
//! ```
//!
//! Extension chain (optional, present iff the header's `extension`
//! byte is non-zero):
//!
//! ```text
//! +---------------+---------------+----------------------+
//! | next_ext      | len           | data...              |
//! +---------------+---------------+----------------------+
//! ```
//!
//! `next_ext == 0` terminates the chain. `len` must be a multiple of 4
//! per BEP 29. The selective-ack extension uses type id 1.

use crate::error::{Error, Result};

/// Wire size of the fixed µTP header.
pub const HEADER_LEN: usize = 20;

/// µTP protocol version. Always 1 in BEP 29.
pub const VERSION: u8 = 1;

/// Extension id 0 = end of chain (no further extensions).
pub const EXT_NONE: u8 = 0;
/// Extension id 1 = selective acknowledgments.
pub const EXT_SELECTIVE_ACK: u8 = 1;

/// Five packet types per BEP 29. Encoded in the upper 4 bits of the
/// first header byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Carries application bytes in the payload.
    Data,
    /// Connection close — sender will send no more data.
    Fin,
    /// Pure acknowledgement — no payload, exists solely to advance
    /// the peer's ack_nr / wnd_size.
    State,
    /// Hard reset; peer should treat the connection as dead.
    Reset,
    /// Connection establishment — first packet from initiator.
    Syn,
}

impl PacketType {
    fn to_nibble(self) -> u8 {
        match self {
            PacketType::Data => 0,
            PacketType::Fin => 1,
            PacketType::State => 2,
            PacketType::Reset => 3,
            PacketType::Syn => 4,
        }
    }

    fn from_nibble(v: u8) -> Result<Self> {
        match v {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Fin),
            2 => Ok(PacketType::State),
            3 => Ok(PacketType::Reset),
            4 => Ok(PacketType::Syn),
            other => Err(Error::Network(format!("utp: unknown packet type {other}"))),
        }
    }
}

/// One extension entry in the µTP extension chain. We surface the
/// raw data so callers (e.g. the selective-ack handler) can parse
/// per-extension semantics; this struct doesn't itself interpret
/// the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub kind: u8,
    pub data: Vec<u8>,
}

/// A fully decoded µTP packet. Cheap to construct/move — payload
/// is held by-value so the caller owns the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub connection_id: u16,
    pub timestamp_micros: u32,
    pub timestamp_diff_micros: u32,
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
    pub extensions: Vec<Extension>,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Build a minimal packet with no extensions and an empty
    /// payload. Convenience for the common case (SYN / STATE / FIN /
    /// RESET); DATA packets typically use the field initializer
    /// directly so the payload assignment is explicit.
    pub fn new(packet_type: PacketType, connection_id: u16, seq_nr: u16, ack_nr: u16) -> Self {
        Self {
            packet_type,
            connection_id,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: 0,
            seq_nr,
            ack_nr,
            extensions: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Encode to wire bytes. Always produces a valid µTP packet,
    /// extensions in the order they were stored.
    pub fn encode(&self) -> Vec<u8> {
        let ext_bytes = encode_extension_chain(&self.extensions);
        let mut out = Vec::with_capacity(HEADER_LEN + ext_bytes.len() + self.payload.len());

        // Byte 0: type (high nibble) | version (low nibble).
        let type_nibble = self.packet_type.to_nibble();
        out.push((type_nibble << 4) | (VERSION & 0x0F));

        // Byte 1: extension type of the first entry, or 0 if none.
        let first_ext = self.extensions.first().map(|e| e.kind).unwrap_or(EXT_NONE);
        out.push(first_ext);

        out.extend_from_slice(&self.connection_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp_micros.to_be_bytes());
        out.extend_from_slice(&self.timestamp_diff_micros.to_be_bytes());
        out.extend_from_slice(&self.wnd_size.to_be_bytes());
        out.extend_from_slice(&self.seq_nr.to_be_bytes());
        out.extend_from_slice(&self.ack_nr.to_be_bytes());

        out.extend_from_slice(&ext_bytes);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a packet from the start of `buf`. The caller is
    /// expected to pass exactly one µTP datagram — extra trailing
    /// bytes after `header + extensions + payload` are not allowed
    /// because there's no length field. `payload` is whatever
    /// remains after the extension chain.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Network(format!(
                "utp: packet too short: {} bytes, need at least {HEADER_LEN}",
                buf.len()
            )));
        }
        let type_ver = buf[0];
        let packet_type = PacketType::from_nibble(type_ver >> 4)?;
        let version = type_ver & 0x0F;
        if version != VERSION {
            return Err(Error::Network(format!(
                "utp: unsupported version {version}, expected {VERSION}"
            )));
        }
        let first_ext = buf[1];
        let connection_id = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp_micros = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let timestamp_diff_micros = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let wnd_size = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let seq_nr = u16::from_be_bytes([buf[16], buf[17]]);
        let ack_nr = u16::from_be_bytes([buf[18], buf[19]]);

        let mut extensions = Vec::new();
        let mut cursor = HEADER_LEN;
        let mut next_ext = first_ext;
        while next_ext != EXT_NONE {
            if cursor + 2 > buf.len() {
                return Err(Error::Network(
                    "utp: truncated extension chain header".into(),
                ));
            }
            let this_kind = next_ext;
            next_ext = buf[cursor];
            let len = buf[cursor + 1] as usize;
            // BEP 29 requires extension `len` to be a multiple of 4.
            // Tolerate non-multiples on receive (some clients are
            // sloppy) but bail if the body would overrun the buffer.
            cursor += 2;
            if cursor + len > buf.len() {
                return Err(Error::Network(format!(
                    "utp: extension body overflows packet: cursor={cursor} len={len} bufsize={}",
                    buf.len()
                )));
            }
            extensions.push(Extension {
                kind: this_kind,
                data: buf[cursor..cursor + len].to_vec(),
            });
            cursor += len;
            // Loop continues with the new `next_ext` value taken
            // from this entry's first byte.
        }
        let payload = buf[cursor..].to_vec();

        Ok(Self {
            packet_type,
            connection_id,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            seq_nr,
            ack_nr,
            extensions,
            payload,
        })
    }
}

fn encode_extension_chain(extensions: &[Extension]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, ext) in extensions.iter().enumerate() {
        // Each entry starts with the type of the NEXT entry. The
        // type of THIS entry was written in the previous byte (or
        // in the header's `extension` byte for the first entry).
        let next_kind = extensions.get(i + 1).map(|e| e.kind).unwrap_or(EXT_NONE);
        out.push(next_kind);
        // `len` byte is the count of data bytes. We don't pad to a
        // multiple of 4 on encode — the data we hand the codec is
        // already-sized for the extension we're sending (e.g. SACK
        // bitmasks are a multiple of 4 by construction).
        out.push(ext.data.len() as u8);
        out.extend_from_slice(&ext.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state_packet() -> Packet {
        Packet {
            packet_type: PacketType::State,
            connection_id: 0xABCD,
            timestamp_micros: 0x01020304,
            timestamp_diff_micros: 0x05060708,
            wnd_size: 0x000F4240, // 1_000_000
            seq_nr: 0x1111,
            ack_nr: 0x2222,
            extensions: Vec::new(),
            payload: Vec::new(),
        }
    }

    #[test]
    fn encode_then_decode_state_packet_roundtrips() {
        let p = sample_state_packet();
        let wire = p.encode();
        assert_eq!(wire.len(), HEADER_LEN);
        let back = Packet::decode(&wire).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn encode_data_packet_includes_payload() {
        let mut p = sample_state_packet();
        p.packet_type = PacketType::Data;
        p.payload = b"hello, swarm".to_vec();
        let wire = p.encode();
        assert_eq!(wire.len(), HEADER_LEN + p.payload.len());
        let back = Packet::decode(&wire).unwrap();
        assert_eq!(back.payload, p.payload);
        assert_eq!(back.packet_type, PacketType::Data);
    }

    #[test]
    fn encode_packet_with_selective_ack_extension() {
        let mut p = sample_state_packet();
        p.extensions = vec![Extension {
            kind: EXT_SELECTIVE_ACK,
            data: vec![0b0000_0001, 0, 0, 0],
        }];
        let wire = p.encode();
        // Header (20) + ext header (2) + ext data (4) = 26 bytes.
        assert_eq!(wire.len(), HEADER_LEN + 2 + 4);
        // The first-extension byte in the header must point to SACK.
        assert_eq!(wire[1], EXT_SELECTIVE_ACK);
        // After the SACK entry, next_ext should be EXT_NONE.
        assert_eq!(wire[HEADER_LEN], EXT_NONE);
        let back = Packet::decode(&wire).unwrap();
        assert_eq!(back.extensions.len(), 1);
        assert_eq!(back.extensions[0].kind, EXT_SELECTIVE_ACK);
        assert_eq!(back.extensions[0].data, vec![0b0000_0001, 0, 0, 0]);
    }

    #[test]
    fn version_nibble_is_one() {
        let p = sample_state_packet();
        let wire = p.encode();
        assert_eq!(wire[0] & 0x0F, VERSION);
    }

    #[test]
    fn packet_type_nibble_is_high_bits() {
        for (pt, nibble) in [
            (PacketType::Data, 0u8),
            (PacketType::Fin, 1),
            (PacketType::State, 2),
            (PacketType::Reset, 3),
            (PacketType::Syn, 4),
        ] {
            let p = Packet::new(pt, 1, 1, 1);
            let wire = p.encode();
            assert_eq!(wire[0] >> 4, nibble, "unexpected nibble for {pt:?}");
            let back = Packet::decode(&wire).unwrap();
            assert_eq!(back.packet_type, pt);
        }
    }

    #[test]
    fn decode_rejects_too_short_buffer() {
        let buf = vec![0u8; HEADER_LEN - 1];
        assert!(Packet::decode(&buf).is_err());
    }

    #[test]
    fn decode_rejects_unknown_packet_type() {
        let mut wire = sample_state_packet().encode();
        // Type nibble = 7 (out of range), version nibble = 1.
        wire[0] = (7 << 4) | 1;
        assert!(Packet::decode(&wire).is_err());
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut wire = sample_state_packet().encode();
        // Type = State (2), version = 2 (only 1 supported).
        wire[0] = (2 << 4) | 2;
        assert!(Packet::decode(&wire).is_err());
    }

    #[test]
    fn decode_rejects_truncated_extension_chain() {
        let mut wire = sample_state_packet().encode();
        // Claim an extension follows but truncate before it lands.
        wire[1] = EXT_SELECTIVE_ACK;
        // Buffer has no room for the extension's 2-byte header.
        assert!(Packet::decode(&wire).is_err());
    }

    #[test]
    fn decode_rejects_extension_body_overflow() {
        // Build a packet with a SACK extension claiming 200 bytes
        // of body but provide only 0. Decode must reject.
        let mut wire = sample_state_packet().encode();
        wire[1] = EXT_SELECTIVE_ACK;
        // First extension header: next_ext = 0, len = 200, then nothing.
        wire.push(EXT_NONE);
        wire.push(200);
        assert!(Packet::decode(&wire).is_err());
    }

    #[test]
    fn decode_handles_multi_extension_chain() {
        // Two extensions both of kind SACK (kind=1), terminated.
        let mut p = sample_state_packet();
        p.extensions = vec![
            Extension {
                kind: EXT_SELECTIVE_ACK,
                data: vec![1, 2, 3, 4],
            },
            Extension {
                kind: EXT_SELECTIVE_ACK,
                data: vec![5, 6, 7, 8],
            },
        ];
        let wire = p.encode();
        let back = Packet::decode(&wire).unwrap();
        assert_eq!(back.extensions.len(), 2);
        assert_eq!(back.extensions[0].data, vec![1, 2, 3, 4]);
        assert_eq!(back.extensions[1].data, vec![5, 6, 7, 8]);
    }
}
