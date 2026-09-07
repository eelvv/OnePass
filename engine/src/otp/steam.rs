//! Steam guard code (TOTP variant with the Steam alphabet).
//!
//! Steam has no official spec; the widely used algorithm (as implemented by
//! Aegis, andOTP, KeePassXC) is TOTP (SHA-1, 30s window) with the final code
//! encoded in a 26-character alphabet instead of digits.

use crate::error::{Error, Result};
use crate::otp::hotp;
use crate::otp::types::HashAlgorithm;

const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_DIGITS: usize = 5;

/// Generates a Steam guard code (5 chars) at `time_secs`.
pub fn steam(secret: &[u8], period: u64, time_secs: u64) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod(period));
    }
    let counter = time_secs / period;
    let hash = hotp::hmac(HashAlgorithm::Sha1, secret, &counter.to_be_bytes())?;
    let mut code = u64::from(hotp::truncate4(&hash));
    let mut out = [0u8; STEAM_DIGITS];
    // Steam appends the least-significant alphabet index first (unlike the
    // base-26 Yandex encoding, which is big-endian).
    for slot in &mut out {
        *slot = STEAM_ALPHABET[(code % 26) as usize];
        code /= 26;
    }
    Ok(String::from_utf8(out.to_vec()).expect("steam alphabet is ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_membership_and_length() {
        // Must always produce exactly 5 chars from the Steam alphabet.
        let secret = b"12345678901234567890";
        for t in [59u64, 1_111_111_109, 1_234_567_890, 2_000_000_000] {
            let code = steam(secret, 30, t).unwrap();
            assert_eq!(code.len(), 5);
            for ch in code.chars() {
                assert!(
                    STEAM_ALPHABET.contains(&(ch as u8)),
                    "char {ch} not in alphabet"
                );
            }
        }
    }

    #[test]
    fn deterministic() {
        let secret = b"12345678901234567890";
        let a = steam(secret, 30, 59).unwrap();
        let b = steam(secret, 30, 59).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, steam(secret, 30, 60).unwrap());
    }
}
