use sha1::{Digest, Sha1};

/// Returns true iff SHA1(data) matches the expected hash.
/// Critical correctness gate — only data that passes this check is ever written to disk.
pub fn verify_piece(data: &[u8], expected: &[u8; 20]) -> bool {
    let digest = Sha1::digest(data);
    digest.as_slice() == expected.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_sha1() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert!(verify_piece(b"abc", &expected));
        assert!(!verify_piece(b"abd", &expected));
    }
}
