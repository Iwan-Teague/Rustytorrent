use std::collections::BTreeMap;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BencodeValue {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<BencodeValue>),
    Dict(BTreeMap<Vec<u8>, BencodeValue>),
}

impl BencodeValue {
    pub fn parse(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
        parse_value(input)
    }

    pub fn parse_all(input: &[u8]) -> Result<BencodeValue> {
        let (v, rest) = parse_value(input)?;
        if !rest.is_empty() {
            return Err(Error::Bencode(format!(
                "trailing bytes after root value: {} bytes",
                rest.len()
            )));
        }
        Ok(v)
    }

    pub fn as_int(&self) -> Result<i64> {
        match self {
            BencodeValue::Int(i) => Ok(*i),
            _ => Err(Error::Bencode("expected integer".into())),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            BencodeValue::Bytes(b) => Ok(b),
            _ => Err(Error::Bencode("expected byte string".into())),
        }
    }

    pub fn as_str(&self) -> Result<&str> {
        let b = self.as_bytes()?;
        std::str::from_utf8(b).map_err(|e| Error::Bencode(format!("invalid utf-8: {e}")))
    }

    pub fn as_list(&self) -> Result<&[BencodeValue]> {
        match self {
            BencodeValue::List(v) => Ok(v),
            _ => Err(Error::Bencode("expected list".into())),
        }
    }

    pub fn as_dict(&self) -> Result<&BTreeMap<Vec<u8>, BencodeValue>> {
        match self {
            BencodeValue::Dict(d) => Ok(d),
            _ => Err(Error::Bencode("expected dict".into())),
        }
    }

    pub fn dict_get(&self, key: &[u8]) -> Result<&BencodeValue> {
        self.as_dict()?
            .get(key)
            .ok_or_else(|| Error::Bencode(format!("missing key: {}", String::from_utf8_lossy(key))))
    }
}

fn parse_value(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
    let first = *input
        .first()
        .ok_or_else(|| Error::Bencode("unexpected EOF".into()))?;
    match first {
        b'i' => parse_int(input),
        b'l' => parse_list(input),
        b'd' => parse_dict(input),
        b'0'..=b'9' => parse_bytes(input),
        c => Err(Error::Bencode(format!("unexpected byte 0x{c:02x}"))),
    }
}

fn parse_int(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
    debug_assert_eq!(input[0], b'i');
    let body = &input[1..];
    let end = body
        .iter()
        .position(|&b| b == b'e')
        .ok_or_else(|| Error::Bencode("unterminated integer".into()))?;
    let digits = &body[..end];
    if digits.is_empty() {
        return Err(Error::Bencode("empty integer".into()));
    }
    let s = std::str::from_utf8(digits).map_err(|e| Error::Bencode(format!("int utf-8: {e}")))?;
    if s == "-0" {
        return Err(Error::Bencode("negative zero".into()));
    }
    if s.len() > 1 && (s.starts_with('0') || s.starts_with("-0")) {
        return Err(Error::Bencode("leading zero".into()));
    }
    let n: i64 = s
        .parse()
        .map_err(|e| Error::Bencode(format!("int parse: {e}")))?;
    Ok((BencodeValue::Int(n), &body[end + 1..]))
}

fn parse_bytes(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
    let colon = input
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| Error::Bencode("byte string missing colon".into()))?;
    let len_str = std::str::from_utf8(&input[..colon])
        .map_err(|e| Error::Bencode(format!("len utf-8: {e}")))?;
    let len: usize = len_str
        .parse()
        .map_err(|e| Error::Bencode(format!("byte string len: {e}")))?;
    let rest = &input[colon + 1..];
    if rest.len() < len {
        return Err(Error::Bencode(format!(
            "byte string too short: need {} have {}",
            len,
            rest.len()
        )));
    }
    let (val, rest) = rest.split_at(len);
    Ok((BencodeValue::Bytes(val.to_vec()), rest))
}

fn parse_list(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
    debug_assert_eq!(input[0], b'l');
    let mut rest = &input[1..];
    let mut items = Vec::new();
    loop {
        match rest.first() {
            Some(b'e') => return Ok((BencodeValue::List(items), &rest[1..])),
            None => return Err(Error::Bencode("unterminated list".into())),
            _ => {
                let (v, r) = parse_value(rest)?;
                items.push(v);
                rest = r;
            }
        }
    }
}

fn parse_dict(input: &[u8]) -> Result<(BencodeValue, &[u8])> {
    debug_assert_eq!(input[0], b'd');
    let mut rest = &input[1..];
    let mut map: BTreeMap<Vec<u8>, BencodeValue> = BTreeMap::new();
    let mut prev_key: Option<Vec<u8>> = None;
    loop {
        match rest.first() {
            Some(b'e') => return Ok((BencodeValue::Dict(map), &rest[1..])),
            None => return Err(Error::Bencode("unterminated dict".into())),
            _ => {
                let (k, r) = parse_bytes(rest)?;
                let key = match k {
                    BencodeValue::Bytes(b) => b,
                    _ => unreachable!(),
                };
                if let Some(pk) = &prev_key {
                    if &key <= pk {
                        return Err(Error::Bencode("dict keys not sorted or duplicated".into()));
                    }
                }
                let (v, r) = parse_value(r)?;
                prev_key = Some(key.clone());
                map.insert(key, v);
                rest = r;
            }
        }
    }
}

/// Skip a single bencode value and return how many bytes it occupies.
/// Used to find the raw byte span of the `info` dictionary so its SHA1
/// hash matches the original encoding exactly.
pub fn skip_value(input: &[u8]) -> Result<usize> {
    let len_before = input.len();
    let (_v, rest) = parse_value(input)?;
    Ok(len_before - rest.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(b: &[u8]) -> BencodeValue {
        BencodeValue::parse_all(b).unwrap()
    }

    #[test]
    fn integer() {
        assert_eq!(parse_all(b"i42e"), BencodeValue::Int(42));
        assert_eq!(parse_all(b"i-7e"), BencodeValue::Int(-7));
        assert_eq!(parse_all(b"i0e"), BencodeValue::Int(0));
    }

    #[test]
    fn integer_rejects_leading_zero() {
        assert!(BencodeValue::parse_all(b"i03e").is_err());
        assert!(BencodeValue::parse_all(b"i-0e").is_err());
    }

    #[test]
    fn integer_rejects_empty() {
        assert!(BencodeValue::parse_all(b"ie").is_err());
    }

    #[test]
    fn byte_string() {
        assert_eq!(parse_all(b"4:spam"), BencodeValue::Bytes(b"spam".to_vec()));
        assert_eq!(parse_all(b"0:"), BencodeValue::Bytes(vec![]));
    }

    #[test]
    fn byte_string_with_binary() {
        let raw = b"5:\x00\x01\x02\x03\xff";
        assert_eq!(parse_all(raw), BencodeValue::Bytes(vec![0, 1, 2, 3, 0xff]));
    }

    #[test]
    fn empty_list() {
        assert_eq!(parse_all(b"le"), BencodeValue::List(vec![]));
    }

    #[test]
    fn list_of_mixed() {
        let v = parse_all(b"li42e4:spame");
        assert_eq!(
            v,
            BencodeValue::List(vec![
                BencodeValue::Int(42),
                BencodeValue::Bytes(b"spam".to_vec())
            ])
        );
    }

    #[test]
    fn empty_dict() {
        assert_eq!(parse_all(b"de"), BencodeValue::Dict(BTreeMap::new()));
    }

    #[test]
    fn dict_of_two() {
        let v = parse_all(b"d3:cow3:moo4:spam4:eggse");
        let mut expected = BTreeMap::new();
        expected.insert(b"cow".to_vec(), BencodeValue::Bytes(b"moo".to_vec()));
        expected.insert(b"spam".to_vec(), BencodeValue::Bytes(b"eggs".to_vec()));
        assert_eq!(v, BencodeValue::Dict(expected));
    }

    #[test]
    fn nested_dict() {
        let v = parse_all(b"d4:listli1ei2ei3eee");
        let list = BencodeValue::List(vec![
            BencodeValue::Int(1),
            BencodeValue::Int(2),
            BencodeValue::Int(3),
        ]);
        let mut expected = BTreeMap::new();
        expected.insert(b"list".to_vec(), list);
        assert_eq!(v, BencodeValue::Dict(expected));
    }

    #[test]
    fn dict_rejects_unsorted_keys() {
        assert!(BencodeValue::parse_all(b"d4:spam4:eggs3:cow3:mooe").is_err());
    }

    #[test]
    fn dict_rejects_duplicate_keys() {
        assert!(BencodeValue::parse_all(b"d3:cow3:moo3:cow3:fooe").is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert!(BencodeValue::parse_all(b"i1eXX").is_err());
    }

    #[test]
    fn skip_returns_byte_count() {
        assert_eq!(skip_value(b"i42e").unwrap(), 4);
        assert_eq!(skip_value(b"4:spam").unwrap(), 6);
        assert_eq!(skip_value(b"le").unwrap(), 2);
        assert_eq!(skip_value(b"d3:cow3:mooe").unwrap(), 12);
    }
}
