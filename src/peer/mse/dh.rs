//! Diffie-Hellman key exchange for MSE/PE. Fixed 768-bit MODP group from
//! BEP 8 (same as RFC 2409 Oakley Group 1), generator 2.
//!
//! `num-bigint` does the heavy lifting of variable-length modular
//! exponentiation. The actual BitTorrent-specific layer above only cares
//! about (a) generating a private exponent, (b) computing the public Y,
//! and (c) computing the shared secret S — all returned as 96 big-endian
//! bytes (zero-padded if the value is shorter than 768 bits).

use num_bigint::BigUint;
use num_traits::{Num, One};
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
        // Wipe the raw entropy buffer; the BigUint owns its own copy now.
        use zeroize::Zeroize;
        bytes.zeroize();
        Keypair { private, public }
    }

    /// Compute the shared secret given the other party's public key.
    pub fn shared_secret(&self, peer_public: &BigUint) -> BigUint {
        peer_public.modpow(&self.private, &p())
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        // Best-effort only — NOT a true secret wipe. Assigning zero
        // *deallocates* the old limb buffer rather than scrubbing it, so
        // the private exponent's bytes may linger in freed heap until
        // reused. num-bigint exposes no safe in-place limb-zeroing API,
        // and this crate forbids `unsafe` outside the sandbox FFI, so we
        // can't do better here without pulling in a different bignum.
        //
        // Acceptable because MSE/PE is wire *obfuscation*, not
        // confidentiality: the DH keys are per-connection ephemeral and
        // grant no lasting secret. The values that DO matter downstream —
        // the derived RC4 keystream state — are properly `ZeroizeOnDrop`.
        self.private = BigUint::from(0u32);
        self.public = BigUint::from(0u32);
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

/// Validate a received peer public key against degenerate / malicious values.
///
/// A well-behaved peer's `Y = g^x mod p` lies strictly between 1 and p-1.
/// An adversary who sends `Y ∈ {0, 1, p-1, p}` forces the shared secret
/// `S = Y^our_x mod p` into a degenerate value (0, 1, or ±1), which would
/// then key our RC4 stream — catastrophically predictable.
///
/// This is the standard MODP "subgroup confinement" defense; cheap because
/// the bigint compare is constant in `p` width regardless of `Y`.
pub fn validate_peer_public(y: &BigUint) -> Result<(), &'static str> {
    let p_minus_one: BigUint = p() - BigUint::one();
    if y <= &BigUint::one() {
        return Err("peer public key <= 1");
    }
    if y >= &p_minus_one {
        return Err("peer public key >= p-1");
    }
    Ok(())
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

    #[test]
    fn validate_rejects_degenerate_values() {
        // 0, 1, p-1, p — all force the shared secret to be a known small value.
        assert!(validate_peer_public(&BigUint::from(0u32)).is_err());
        assert!(validate_peer_public(&BigUint::from(1u32)).is_err());
        let p_val = p();
        assert!(validate_peer_public(&(&p_val - BigUint::one())).is_err());
        assert!(validate_peer_public(&p_val).is_err());
    }

    #[test]
    fn validate_accepts_normal_public_key() {
        // Any honestly-generated keypair must pass.
        for _ in 0..16 {
            let kp = Keypair::generate();
            assert!(validate_peer_public(&kp.public).is_ok());
        }
    }
}
