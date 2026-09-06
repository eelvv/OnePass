//! Hexadecimal encoding (lowercase).

use crate::error::{Error, Result};

/// Encodes bytes as a lowercase hex string.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodes a hex string (case-insensitive).
pub fn decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Encoding("hex string has odd length".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| Error::Encoding(format!("invalid hex at position {i}")))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_lowercase() {
        assert_eq!(encode(b"\xde\xad\xbe\xef"), "deadbeef");
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn decode_roundtrip() {
        assert_eq!(decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
        assert_eq!(decode("DEADBEEF").unwrap(), b"\xde\xad\xbe\xef");
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
