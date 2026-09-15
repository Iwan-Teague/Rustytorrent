//! Plain RC4 stream cipher (RFC ... actually RC4 was never an RFC, but it's
//! the Schneier-textbook variant). 256-byte S-box, key-schedule sets up the
//! permutation, then PRGA produces keystream bytes.
//!
//! Used for BEP-8 MSE/PE: after the handshake key exchange, RC4 encrypts the
//! ENTIRE peer stream in each direction (BEP-8 full-encryption mode — all piece
//! and control traffic; see `stream.rs`), not just the handshake. BitTorrent
//! specs hardcoded RC4 in 2006. It is cryptographically broken; we treat MSE as
//! obfuscation of public swarm data, not encryption-of-record (see ANONYMITY.md).
//!
//! `Zeroize` wipes the S-box and indices on drop so the keystream state
//! doesn't survive in heap-snapshot core dumps or freed-page reuse.
//!
//! Charter exemption (ADR-012 X2 / T2 §K): covered by the dated
//! `# suite-exemption: BEP-8 MSE RC4 ... full-session ... non-confidential;
//! expires 2027-03-01` row in deny.toml. Non-confidential use ONLY — this
//! primitive provides NO integrity and NO real confidentiality (see the
//! `tampering_is_undetected` / `wrong_key_produces_garbage` negative tests
//! below); do not reuse it anywhere confidentiality or authenticity matters.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stateful RC4 keystream generator.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initialise the S-box from `key` (the BT MSE key derivation feeds in
    /// a 20-byte SHA-1 digest).
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must be non-empty");
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Encrypt (or decrypt — RC4 is symmetric) `data` in place by XORing
    /// each byte with the next keystream byte.
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }

    /// Advance the keystream by `n` bytes without touching any payload.
    /// MSE requires both sides discard the first 1024 bytes of output
    /// to dodge the Fluhrer–Mantin–Shamir weak-key attack.
    pub fn skip(&mut self, n: usize) {
        let mut sink = vec![0u8; n];
        self.process(&mut sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from the original RC4 description: key "Key" / plaintext
    /// "Plaintext" → ciphertext BB F3 16 E8 D9 40 AF 0A D3.
    #[test]
    fn known_test_vector() {
        let mut rc4 = Rc4::new(b"Key");
        let mut buf = b"Plaintext".to_vec();
        rc4.process(&mut buf);
        assert_eq!(buf, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    /// Encrypt-then-decrypt with the same key recovers the plaintext.
    #[test]
    fn roundtrip() {
        let plain = b"BitTorrent protocol with some longer data to exercise the keystream";
        let mut enc = Rc4::new(b"shared-secret-bytes");
        let mut dec = Rc4::new(b"shared-secret-bytes");
        let mut buf = plain.to_vec();
        enc.process(&mut buf);
        assert_ne!(buf, plain);
        dec.process(&mut buf);
        assert_eq!(buf, plain);
    }

    /// Skipping `n` keystream bytes is the same as processing them.
    #[test]
    fn skip_matches_process() {
        let mut a = Rc4::new(b"abc");
        let mut b = Rc4::new(b"abc");
        a.skip(100);
        let mut zeros = vec![0u8; 100];
        b.process(&mut zeros);
        // Both should now produce the same next byte.
        let mut x = [0u8; 1];
        let mut y = [0u8; 1];
        a.process(&mut x);
        b.process(&mut y);
        assert_eq!(x, y);
    }

    // --- Negative / edge tests (T1 P3: hand-rolled crypto needs negative tests;
    // several ALSO pin the security NON-properties that justify the X2
    // "obfuscation, not security" exemption — see the module docs). ---

    /// Confidentiality is key-dependent: decrypting with the wrong key yields
    /// garbage, not the plaintext.
    #[test]
    fn wrong_key_produces_garbage() {
        let plain = b"BitTorrent protocol handshake payload bytes";
        let mut enc = Rc4::new(b"correct-key");
        let mut dec = Rc4::new(b"different-key");
        let mut buf = plain.to_vec();
        enc.process(&mut buf);
        dec.process(&mut buf);
        assert_ne!(buf, plain, "wrong key must not recover the plaintext");
    }

    /// RC4 provides NO integrity/authentication: a flipped ciphertext byte
    /// decrypts to a correspondingly flipped plaintext byte, silently, with no
    /// error. This documents WHY MSE is obfuscation-not-security — anything
    /// needing tamper-evidence must layer a MAC on top (rustytorrent does not
    /// rely on RC4 for integrity; piece integrity is SHA-1 over public data).
    #[test]
    fn tampering_is_undetected() {
        let plain = b"exactly-known-plaintext!";
        let mut enc = Rc4::new(b"k");
        let mut ct = plain.to_vec();
        enc.process(&mut ct);
        ct[3] ^= 0x01; // attacker flips one ciphertext bit
        let mut dec = Rc4::new(b"k");
        dec.process(&mut ct);
        // Decryption "succeeds" (no error path exists) and the tamper maps
        // straight through to plaintext[3] — i.e. it is NOT detected.
        assert_eq!(ct[3], plain[3] ^ 0x01);
        assert_eq!(&ct[..3], &plain[..3], "only the tampered byte changes");
    }

    /// Distinct keys yield distinct keystreams over the same (zero) input.
    #[test]
    fn distinct_keys_distinct_keystream() {
        let mut a = Rc4::new(b"key-a");
        let mut b = Rc4::new(b"key-b");
        let (mut xa, mut xb) = (vec![0u8; 64], vec![0u8; 64]);
        a.process(&mut xa);
        b.process(&mut xb);
        assert_ne!(xa, xb, "different keys must not share a keystream");
    }

    /// Empty input is a no-op and does not advance the keystream.
    #[test]
    fn empty_input_is_noop() {
        let mut a = Rc4::new(b"abc");
        let mut b = Rc4::new(b"abc");
        let mut empty: [u8; 0] = [];
        a.process(&mut empty); // must not panic or advance state
        let (mut x, mut y) = ([0u8; 4], [0u8; 4]);
        a.process(&mut x);
        b.process(&mut y);
        assert_eq!(
            x, y,
            "processing an empty slice must not advance the keystream"
        );
    }

    /// A key longer than the 256-byte S-box is handled by the `key[i % len]`
    /// schedule without panic and still round-trips.
    #[test]
    fn long_key_beyond_sbox_roundtrips() {
        let key = vec![0xABu8; 300];
        let plain = b"payload";
        let mut enc = Rc4::new(&key);
        let mut dec = Rc4::new(&key);
        let mut buf = plain.to_vec();
        enc.process(&mut buf);
        assert_ne!(buf, plain);
        dec.process(&mut buf);
        assert_eq!(buf, plain);
    }

    /// A one-byte key (minimum non-empty) keys and round-trips.
    #[test]
    fn single_byte_key_roundtrips() {
        let mut enc = Rc4::new(b"x");
        let mut dec = Rc4::new(b"x");
        let mut buf = b"hello world".to_vec();
        enc.process(&mut buf);
        dec.process(&mut buf);
        assert_eq!(buf, b"hello world");
    }

    /// An empty key is rejected (documents the fail-closed precondition).
    #[test]
    #[should_panic(expected = "RC4 key must be non-empty")]
    fn empty_key_panics() {
        let _ = Rc4::new(b"");
    }
}
