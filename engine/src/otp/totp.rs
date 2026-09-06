//! RFC 6238 time-based one-time password.

use crate::error::{Error, Result};
use crate::otp::hotp;
use crate::otp::types::HashAlgorithm;

/// RFC 6238 TOTP.
pub fn totp(
    secret: &[u8],
    period: u64,
    time_secs: u64,
    digits: u32,
    algo: HashAlgorithm,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod(period));
    }
    let counter = time_secs / period;
    hotp::hotp(secret, counter, digits, algo)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B. Secret is ASCII "12345678901234567890", 8 digits,
    // 30s period.
    #[test]
    fn rfc6238_appendix_b_sha1() {
        let secret = b"12345678901234567890";
        let expected = [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (t, code) in expected {
            assert_eq!(
                totp(secret, 30, t, 8, HashAlgorithm::Sha1).unwrap(),
                code,
                "t={t}"
            );
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha256() {
        let secret = b"12345678901234567890";
        let expected = [
            (59u64, "32247374"),
            (1_111_111_109, "34756375"),
            (1_111_111_111, "74584430"),
            (1_234_567_890, "42829826"),
            (2_000_000_000, "78428693"),
            (20_000_000_000, "24142410"),
        ];
        for (t, code) in expected {
            assert_eq!(
                totp(secret, 30, t, 8, HashAlgorithm::Sha256).unwrap(),
                code,
                "t={t}"
            );
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha512() {
        let secret = b"12345678901234567890";
        let expected = [
            (59u64, "69342147"),
            (1_111_111_109, "63049338"),
            (1_111_111_111, "54380122"),
            (1_234_567_890, "76671578"),
            (2_000_000_000, "56464532"),
            (20_000_000_000, "69481994"),
        ];
        for (t, code) in expected {
            assert_eq!(
                totp(secret, 30, t, 8, HashAlgorithm::Sha512).unwrap(),
                code,
                "t={t}"
            );
        }
    }

    #[test]
    fn period_zero_rejected() {
        assert!(totp(b"k", 0, 59, 6, HashAlgorithm::Sha1).is_err());
    }
}
