//! RFC 4648 Base32 (independently implemented).

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes `data` as Base32 with `=` padding (RFC 4648).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1F) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[index] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

/// Decodes a Base32 string. Accepts lowercase; leftover trailing bits are
/// ignored (lenient, matching common OTP tooling).
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut seen_padding = false;

    for ch in input.chars() {
        if ch == '=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            return Err(Error::Encoding(
                "non-padding character after '='".to_string(),
            ));
        }
        let upper = ch.to_ascii_uppercase();
        let value: u32 = match upper {
            'A'..='Z' => u32::from(upper) - u32::from('A'),
            '2'..='7' => u32::from(upper) - u32::from('2') + 26,
            _ => return Err(Error::Encoding(format!("invalid base32 character: {ch}"))),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    // RFC 4648: a trailing group may only be 2, 4, 5, or 7 characters, which
    // leaves 1..=4 leftover bits. 5..=7 leftover bits is an invalid length.
    if bits >= 5 {
        return Err(Error::Encoding("invalid base32 length".to_string()));
    }
    Ok(out)
}

/// Decodes Base32 while tolerating whitespace and `-` (as found in many
/// user-typed secrets).
pub fn decode_tolerant(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    decode(&cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors.
    #[test]
    fn rfc4648_encode() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "MY======");
        assert_eq!(encode(b"fo"), "MZXQ====");
        assert_eq!(encode(b"foo"), "MZXW6===");
        assert_eq!(encode(b"foob"), "MZXW6YQ=");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn rfc4648_decode() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("MY======").unwrap(), b"f");
        assert_eq!(decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn lowercase_accepted() {
        assert_eq!(decode("mzxw6ytboi======").unwrap(), b"foobar");
    }

    #[test]
    fn tolerant_drops_whitespace_and_dashes() {
        assert_eq!(decode_tolerant("MZ XW-6YTB").unwrap(), b"fooba");
    }

    #[test]
    fn roundtrip_random() {
        for len in 0..64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = encode(&data);
            assert_eq!(decode(&encoded).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn rejects_invalid() {
        assert!(decode("1").is_err()); // '1' not in alphabet
        assert!(decode("A").is_err()); // invalid length (5 leftover bits)
        assert!(decode("AAAA=A").is_err()); // padding in middle
    }
}
