//! 160-bit node identifier and XOR distance.
//!
//! The DHT uses the same 160-bit space as info-hashes. Distance between two
//! IDs is the bitwise XOR interpreted as an unsigned integer; the routing
//! table indexes contacts by the position of the highest bit where the
//! contact differs from our own ID (the "bucket index").

use std::fmt;

use rand::RngCore;

/// 20-byte (160-bit) identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    pub fn random() -> Self {
        let mut buf = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn from_bytes(b: [u8; 20]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// XOR distance. The result is a 20-byte big-endian unsigned integer.
    pub fn distance(&self, other: &NodeId) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (slot, (a, b)) in out.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *slot = a ^ b;
        }
        out
    }

    /// Bucket index = 159 - leading_zero_bits(distance).
    /// Returns `None` if the IDs are identical (distance is zero — same node).
    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let d = self.distance(other);
        for (i, byte) in d.iter().enumerate() {
            if *byte != 0 {
                let lz = byte.leading_zeros() as usize;
                let bit_position = i * 8 + lz; // index of the high-bit set
                return Some(159 - bit_position);
            }
        }
        None
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_to_self_is_zero() {
        let id = NodeId::random();
        let d = id.distance(&id);
        assert!(d.iter().all(|b| *b == 0));
        assert_eq!(id.bucket_index(&id), None);
    }

    #[test]
    fn distance_is_xor() {
        let a = NodeId([0u8; 20]);
        let mut b = [0u8; 20];
        b[0] = 0xFF;
        let b = NodeId(b);
        let d = a.distance(&b);
        assert_eq!(d[0], 0xFF);
        assert!(d[1..].iter().all(|x| *x == 0));
    }

    #[test]
    fn bucket_index_highest_differing_bit() {
        // 0xFF in byte 0 → high bit at position 0 (counting from MSB) →
        // bucket index 159 - 0 = 159.
        let a = [0u8; 20];
        let mut b = [0u8; 20];
        b[0] = 0x80; // bit 0 from MSB
        let a = NodeId(a);
        let b = NodeId(b);
        assert_eq!(a.bucket_index(&b), Some(159));

        // 0x01 in byte 0 → bit 7 from MSB → bucket index 159 - 7 = 152.
        let mut c = [0u8; 20];
        c[0] = 0x01;
        let c = NodeId(c);
        assert_eq!(a.bucket_index(&c), Some(152));

        // Last byte differing in low bit → bit 159 from MSB → bucket index 0.
        let mut d = [0u8; 20];
        d[19] = 0x01;
        let d = NodeId(d);
        assert_eq!(a.bucket_index(&d), Some(0));
    }

    #[test]
    fn random_ids_are_unique() {
        let a = NodeId::random();
        let b = NodeId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn display_is_lowercase_hex() {
        let id = NodeId([0xab; 20]);
        assert_eq!(id.to_string(), "abababababababababababababababababababab");
    }
}
