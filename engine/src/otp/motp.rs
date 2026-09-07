//! mobile-OTP (MOTP).
//!
//! Publicly documented algorithm (as used by Aegis/andOTP): the code is the
//! first `digits` hex characters of MD5("{counter}{hex(secret)}{pin}") where
//! counter = time / period (10s windows, 6 digits by default).

use crate::encoding::hex;
use crate::error::{Error, Result};
use md5::{Digest, Md5};

/// Generates a MOTP code (hex digits) at `time_secs`.
pub fn motp(secret: &[u8], pin: &str, period: u64, digits: u32, time_secs: u64) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod(period));
    }
    let counter = time_secs / period;
    let input = format!("{counter}{}{pin}", hex::encode(secret));
    let digest = Md5::digest(input.as_bytes());
    let hex_digest = hex::encode(&digest);
    let n = usize::try_from(digits)
        .unwrap_or(usize::MAX)
        .min(hex_digest.len());
    Ok(hex_digest[..n].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_length() {
        // No official test vectors exist for MOTP; assert shape + determinism
        // and cross-check values in `tests/variants.rs` against an independent
        // computation.
        let secret = hex::decode("1234567890abcdef").unwrap();
        let a = motp(&secret, "1234", 10, 6, 1_700_000_000).unwrap();
        let b = motp(&secret, "1234", 10, 6, 1_700_000_000).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
