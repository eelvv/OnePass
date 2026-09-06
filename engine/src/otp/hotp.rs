//! RFC 4226 HMAC-based one-time password + shared HMAC/truncation helpers.

use crate::error::{Error, Result};
use crate::otp::types::HashAlgorithm;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Computes HMAC over `data` with `key` using the given algorithm.
pub fn hmac(algo: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    macro_rules! run {
        ($t:ty) => {{
            let mut mac = <Hmac<$t>>::new_from_slice(key).map_err(|_| Error::InvalidSecret)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algo {
        HashAlgorithm::Sha1 => run!(Sha1),
        HashAlgorithm::Sha256 => run!(Sha256),
        HashAlgorithm::Sha512 => run!(Sha512),
        HashAlgorithm::Md5 => run!(Md5),
    }
}

/// RFC 4226 §5.4 dynamic truncation (31-bit value).
pub fn truncate4(hash: &[u8]) -> u32 {
    let offset = usize::from(hash[hash.len() - 1] & 0x0F);
    (u32::from(hash[offset] & 0x7F)) << 24
        | (u32::from(hash[offset + 1])) << 16
        | (u32::from(hash[offset + 2])) << 8
        | u32::from(hash[offset + 3])
}

/// 8-byte variant of dynamic truncation (used by Yandex.Key).
pub fn truncate8(hash: &[u8]) -> u64 {
    let offset = usize::from(hash[hash.len() - 1] & 0x0F);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&hash[offset..offset + 8]);
    buf[0] &= 0x7F;
    u64::from_be_bytes(buf)
}

/// Formats a truncated code with zero padding to `digits` (max 10).
pub fn format_code(code: u64, digits: u32) -> Result<String> {
    if digits == 0 || digits > 10 {
        return Err(Error::InvalidDigits(digits));
    }
    let modulus = 10u64
        .checked_pow(digits)
        .ok_or(Error::InvalidDigits(digits))?;
    Ok(format!("{:0width$}", code % modulus, width = digits as usize))
}

/// RFC 4226 HOTP.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algo: HashAlgorithm) -> Result<String> {
    if !algo.is_hmac() {
        return Err(Error::UnsupportedAlgorithm(format!(
            "HOTP with {}",
            algo.as_str()
        )));
    }
    let hash = hmac(algo, secret, &counter.to_be_bytes())?;
    format_code(u64::from(truncate4(&hash)), digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D (SHA1, 6 digits, secret "12345678901234567890").
    #[test]
    fn rfc4226_appendix_d() {
        let secret = b"12345678901234567890";
        let expected = [
            (0u64, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ];
        for (counter, code) in expected {
            assert_eq!(
                hotp(secret, counter, 6, HashAlgorithm::Sha1).unwrap(),
                code,
                "counter={counter}"
            );
        }
    }

    #[test]
    fn hotp_sha256_sha512() {
        let secret = b"12345678901234567890";
        // Cross-checked: same truncation rule, different digest.
        let c = 42u64;
        let h1 = hotp(secret, c, 6, HashAlgorithm::Sha1).unwrap();
        let h256 = hotp(secret, c, 6, HashAlgorithm::Sha256).unwrap();
        let h512 = hotp(secret, c, 6, HashAlgorithm::Sha512).unwrap();
        assert_eq!(h1.len(), 6);
        assert_eq!(h256.len(), 6);
        assert_eq!(h512.len(), 6);
        assert_ne!(h1, h256);
    }

    #[test]
    fn zero_padding() {
        // A code that is 0 must still render as N digits.
        assert_eq!(format_code(0, 6).unwrap(), "000000");
        assert_eq!(format_code(7, 8).unwrap(), "00000007");
    }

    #[test]
    fn md5_rejected_for_hotp() {
        assert!(hotp(b"secret", 0, 6, HashAlgorithm::Md5).is_err());
    }
}
