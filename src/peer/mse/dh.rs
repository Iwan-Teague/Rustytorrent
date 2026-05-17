//! Diffie-Hellman key exchange for MSE/PE. Fixed 768-bit MODP group from
//! BEP 8 (same as RFC 2409 Oakley Group 1), generator 2.
//!
//! `num-bigint` does the heavy lifting of variable-length modular
//! exponentiation. The actual BitTorrent-specific layer above only cares
//! about (a) generating a private exponent, (b) computing the public Y,
//! and (c) computing the shared secret S — all returned as 96 big-endian
//! bytes (zero-padded if the value is shorter than 768 bits).

use num_bigint::BigUint;
use num_traits::Num;
use rand::RngCore;

/// 768-bit prime from BEP 8 (Oakley Group 1, RFC 2409 §6.1).
const P_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563",
);

/// Generator g = 2.
const G: u32 = 2;

/// Public-key / shared-secret width.
pub const KEY_LEN: usize = 96;

/// A private DH exponent. The MSE spec recommends a random 128-to-180 bit
/// integer (`Xa`/`Xb`). We use 160 bits — fits comfortably below the prime
/// and matches what libtorrent does.
const PRIVATE_BITS: usize = 160;

pub struct Keypair {
    pub private: BigUint,
    pub public: BigUint,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; PRIVATE_BITS / 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        // Discard any leading zero so `private` is exactly `PRIVATE_BITS` long.
        bytes[0] |= 0x80;
        let private = BigUint::from_bytes_be(&bytes);
        let public = BigUint::from(G).modpow(&private, &p());
        Keypair { private, public }
    }

    /// Compute the shared secret given the other party's public key.
    pub fn shared_secret(&self, peer_public: &BigUint) -> BigUint {
        peer_public.modpow(&self.private, &p())
    }
}

/// `BigUint` value of the MODP prime. Built lazily on first use.
pub fn p() -> BigUint {
    BigUint::from_str_radix(P_HEX, 16).expect("hard-coded MODP prime parses")
}

/// Encode a `BigUint` to exactly `KEY_LEN` big-endian bytes (left-padded with zeros).
pub fn to_bytes(n: &BigUint) -> [u8; KEY_LEN] {
    let raw = n.to_bytes_be();
    assert!(
        raw.len() <= KEY_LEN,
        "DH value {} bytes exceeds {}",
        raw.len(),
        KEY_LEN
    );
    let mut out = [0u8; KEY_LEN];
    out[KEY_LEN - raw.len()..].copy_from_slice(&raw);
    out
}

/// Parse `KEY_LEN` big-endian bytes back into a `BigUint`.
pub fn from_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_yields_valid_public() {
        let kp = Keypair::generate();
        // public should be < p.
        assert!(kp.public < p());
        // public bytes should fit.
        let bytes = to_bytes(&kp.public);
        assert_eq!(bytes.len(), KEY_LEN);
    }

    #[test]
    fn dh_roundtrip_yields_shared_secret() {
        // Alice and Bob each generate, exchange public keys, derive same secret.
        let a = Keypair::generate();
        let b = Keypair::generate();
        let s_a = a.shared_secret(&b.public);
        let s_b = b.shared_secret(&a.public);
        assert_eq!(s_a, s_b);
        // Sanity: secret bytes are 96.
        assert_eq!(to_bytes(&s_a).len(), KEY_LEN);
    }

    #[test]
    fn bytes_roundtrip() {
        let kp = Keypair::generate();
        let bytes = to_bytes(&kp.public);
        let restored = from_bytes(&bytes);
        assert_eq!(restored, kp.public);
    }
}
