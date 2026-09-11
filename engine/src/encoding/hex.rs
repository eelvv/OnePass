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
///
/// Works on bytes rather than slicing the string, so multi-byte UTF-8 input
/// can never panic on a non-character boundary (the old `&s[i..i + 2]` did).
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Encoding("hex string has odd length".to_string()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(pair[0])
            .ok_or_else(|| Error::Encoding(format!("invalid hex at position {}", i * 2)))?;
        let lo = hex_val(pair[1])
            .ok_or_else(|| Error::Encoding(format!("invalid hex at position {}", i * 2 + 1)))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Value of a single hex digit, or `None` for anything else.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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

    #[test]
    fn multibyte_input_errors_without_panic() {
        // '€' is 3 bytes: two of them make an even byte length, but slicing
        // the *string* at byte offsets lands mid-codepoint and panicked.
        assert!(decode("€€").is_err());
        assert!(decode("€").is_err()); // odd length
        assert!(decode("de€d").is_err());
    }
}
