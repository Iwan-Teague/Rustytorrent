//! Plain RC4 stream cipher (RFC ... actually RC4 was never an RFC, but it's
//! the Schneier-textbook variant). 256-byte S-box, key-schedule sets up the
//! permutation, then PRGA produces keystream bytes.
//!
//! Used only as part of the MSE/PE handshake — BitTorrent specs hardcoded
//! RC4 in 2006. It is cryptographically broken; we treat MSE as obfuscation,
//! not security.

/// Stateful RC4 keystream generator.
#[derive(Clone)]
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
}
