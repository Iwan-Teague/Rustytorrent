//! Small shared helpers used across modules.

/// Lowercase hex encoding of a byte slice (e.g. an info-hash → 40 chars).
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a 40-character hex string into a 20-byte info-hash. Returns
/// `None` on the wrong length or any non-hex character.
pub fn info_hash_from_hex(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let bytes = [0x00, 0x0f, 0xa1, 0xff, 0x42];
        assert_eq!(hex(&bytes), "000fa1ff42");
    }

    #[test]
    fn info_hash_roundtrip() {
        let ih = [0xABu8; 20];
        let s = hex(&ih);
        assert_eq!(s.len(), 40);
        assert_eq!(info_hash_from_hex(&s), Some(ih));
    }

    #[test]
    fn info_hash_rejects_bad_input() {
        assert_eq!(info_hash_from_hex("short"), None);
        assert_eq!(info_hash_from_hex(&"zz".repeat(20)), None); // non-hex
        assert_eq!(info_hash_from_hex(&"00".repeat(19)), None); // 38 chars
    }
}
