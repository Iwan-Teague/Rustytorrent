//! Magnet-link URI parser (BEP 53 / de-facto spec).
//!
//! A magnet URI carries the minimum information needed to bootstrap a
//! download without a `.torrent` file: the info_hash (so peers can be
//! looked up by it in the DHT or trackers) and an optional list of
//! trackers and a display name. The actual info dict — piece hashes,
//! file layout, piece length — is fetched from peers later via BEP 9
//! ut_metadata.
//!
//! Wire shape (only the parts we actually use):
//! ```text
//! magnet:?xt=urn:btih:<info_hash>&tr=<url>&tr=<url>&dn=<name>
//! ```
//!
//! - `xt` (exact topic) is required; value must be `urn:btih:` plus
//!   the info_hash as either lowercase hex (40 chars) or base32-RFC4648
//!   (32 chars). Both forms appear in the wild; we accept either.
//! - `tr` (tracker) may repeat; each value is percent-encoded.
//! - `dn` (display name) is optional, useful for the progress UI only.
//!
//! Other params (`xl`, `as`, `xs`, `kt`, etc.) are accepted-and-ignored
//! per the spec — unknown keys MUST not cause a parse failure.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    pub info_hash: [u8; 20],
    pub display_name: Option<String>,
    pub trackers: Vec<String>,
}

impl MagnetLink {
    /// Parse a `magnet:?…` URI. Returns `Err` if the scheme is wrong,
    /// `xt` is missing, the info_hash isn't a recognizable 40-char hex
    /// or 32-char base32 string, or percent-decoding fails on a value
    /// we needed.
    pub fn parse(uri: &str) -> Result<Self> {
        let query = uri
            .strip_prefix("magnet:?")
            .ok_or_else(|| Error::Bencode("magnet URI must start with `magnet:?`".into()))?;

        let mut info_hash: Option<[u8; 20]> = None;
        let mut display_name: Option<String> = None;
        let mut trackers: Vec<String> = Vec::new();

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| Error::Bencode(format!("magnet param missing `=`: {pair}")))?;
            // Per RFC 3986 query strings are percent-encoded.
            let decoded = percent_decode(v)?;
            match k {
                "xt" => {
                    let s = std::str::from_utf8(&decoded)
                        .map_err(|_| Error::Bencode("magnet xt not utf-8".into()))?;
                    let hash_str = s.strip_prefix("urn:btih:").ok_or_else(|| {
                        Error::Bencode(format!("xt missing urn:btih: prefix: {s}"))
                    })?;
                    info_hash = Some(parse_info_hash(hash_str)?);
                }
                "dn" => {
                    let s = String::from_utf8(decoded)
                        .map_err(|_| Error::Bencode("magnet dn not utf-8".into()))?;
                    display_name = Some(s);
                }
                "tr" => {
                    let s = String::from_utf8(decoded)
                        .map_err(|_| Error::Bencode("magnet tr not utf-8".into()))?;
                    trackers.push(s);
                }
                _ => {
                    // Spec: ignore unknown keys silently. They cover
                    // less-used features (xl exact length, as acceptable
                    // source, kt keyword topic) we don't need.
                }
            }
        }

        let info_hash = info_hash
            .ok_or_else(|| Error::Bencode("magnet URI missing required xt=urn:btih:…".into()))?;

        Ok(Self {
            info_hash,
            display_name,
            trackers,
        })
    }
}

/// Parse an info_hash from either:
/// - 40 lowercase or uppercase hex chars, or
/// - 32 base32 (RFC 4648) chars.
fn parse_info_hash(s: &str) -> Result<[u8; 20]> {
    match s.len() {
        40 => parse_hex_20(s),
        32 => parse_base32_20(s),
        n => Err(Error::Bencode(format!(
            "info_hash must be 40 hex chars or 32 base32 chars, got {n}: {s}"
        ))),
    }
}

fn parse_hex_20(s: &str) -> Result<[u8; 20]> {
    let mut out = [0u8; 20];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        b'A'..=b'F' => Ok(10 + c - b'A'),
        _ => Err(Error::Bencode(format!(
            "non-hex char in info_hash: 0x{c:02x}"
        ))),
    }
}

/// RFC 4648 base32 (A-Z, 2-7), no padding. 32 chars decode to exactly
/// 20 bytes — handy because it's the SHA-1 length.
fn parse_base32_20(s: &str) -> Result<[u8; 20]> {
    let mut out = [0u8; 20];
    let mut bit_buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out_idx = 0usize;
    for c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => 26 + (c - b'2'),
            _ => {
                return Err(Error::Bencode(format!(
                    "non-base32 char in info_hash: 0x{c:02x}"
                )))
            }
        };
        bit_buf = (bit_buf << 5) | (v as u32);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[out_idx] = ((bit_buf >> bits) & 0xff) as u8;
            out_idx += 1;
        }
    }
    if out_idx != 20 {
        return Err(Error::Bencode(format!(
            "base32 info_hash decoded to {out_idx} bytes (expected 20)"
        )));
    }
    Ok(out)
}

/// Minimal `%xx` percent-decoder. `+` is left as `+` (magnet URIs use
/// it as a tracker-URL character, not as a space; only HTML forms do
/// the `+→space` substitution).
fn percent_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Error::Bencode("truncated %XX escape".into()));
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_hex_magnet() {
        let m = MagnetLink::parse("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567")
            .unwrap();
        assert_eq!(
            m.info_hash,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
            ]
        );
        assert!(m.display_name.is_none());
        assert!(m.trackers.is_empty());
    }

    #[test]
    fn parse_with_display_name_and_trackers() {
        let m = MagnetLink::parse(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Some+Name&tr=http%3A%2F%2Ftracker.example%2Fannounce&tr=udp%3A%2F%2Ftracker2.example%3A6969",
        )
        .unwrap();
        // We don't decode `+` to space — that's HTML-form convention,
        // not RFC 3986 query-string convention. So the display name
        // appears verbatim with the `+`.
        assert_eq!(m.display_name.as_deref(), Some("Some+Name"));
        assert_eq!(
            m.trackers,
            vec![
                "http://tracker.example/announce",
                "udp://tracker2.example:6969",
            ]
        );
    }

    #[test]
    fn parse_uppercase_hex() {
        let m = MagnetLink::parse("magnet:?xt=urn:btih:0123456789ABCDEF0123456789ABCDEF01234567")
            .unwrap();
        assert_eq!(m.info_hash[0], 0x01);
        assert_eq!(m.info_hash[19], 0x67);
    }

    #[test]
    fn parse_base32_info_hash() {
        // 20 bytes of value 0x12 → base32-encoded is "CIIQ"... let's compute
        // a known fixture instead: SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        // In base32: 3I42H5IFAHFEZTOY... actually let me just use a known mapping.
        // 20 bytes of 0x00 → 32 base32 chars all 'A'.
        let m = MagnetLink::parse("magnet:?xt=urn:btih:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(m.info_hash, [0u8; 20]);
    }

    #[test]
    fn rejects_missing_xt() {
        assert!(MagnetLink::parse("magnet:?dn=foo").is_err());
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(MagnetLink::parse("http://example/foo").is_err());
    }

    #[test]
    fn rejects_bad_hash_length() {
        assert!(MagnetLink::parse("magnet:?xt=urn:btih:DEADBEEF").is_err());
    }

    #[test]
    fn ignores_unknown_keys() {
        let m = MagnetLink::parse(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&xl=12345&kt=linux",
        )
        .unwrap();
        assert_eq!(m.info_hash[0], 0x01);
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("a%20b").unwrap(), b"a b");
        assert_eq!(percent_decode("%2F%3A").unwrap(), b"/:");
    }

    #[test]
    fn percent_decode_rejects_truncated() {
        assert!(percent_decode("a%2").is_err());
    }
}
