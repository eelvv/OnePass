//! Yandex.Key (yaotp) one-time password.
//!
//! Publicly documented de-facto algorithm (as used by Aegis/andOTP):
//! 1. key = SHA-256(pin || secret); if the first byte is zero it is dropped.
//! 2. counter = time / period (30s windows).
//! 3. h = HMAC-SHA256(key, counter as 8-byte big-endian).
//! 4. dynamic-truncate 8 bytes (offset from last byte & 0x0F, first byte
//!    masked 0x7F) to get a 63-bit value.
//! 5. Encode value % 26^digits in a base-26 lowercase alphabet (8 chars).
//!
//! Secrets: 16 raw bytes (from QR, no checksum) or 26 bytes (with a 12-bit
//! checksum in the last 2 bytes, see [checksum_valid]); secrets are always
//! used truncated to 16 bytes.

use crate::error::{Error, Result};
use crate::otp::hotp;
use sha2::{Digest, Sha256};

/// Yandex secret length without checksum.
pub const SECRET_LENGTH: usize = 16;
/// Yandex secret length with checksum.
pub const SECRET_FULL_LENGTH: usize = 26;

/// Generates a Yandex code at `time_secs`.
pub fn yandex(
    secret: &[u8],
    pin: &str,
    period: u64,
    digits: u32,
    time_secs: u64,
) -> Result<String> {
    if period == 0 {
        return Err(Error::InvalidPeriod(period));
    }
    let secret = normalize_secret(secret)?;

    let mut key_input = Vec::with_capacity(pin.len() + secret.len());
    key_input.extend_from_slice(pin.as_bytes());
    key_input.extend_from_slice(&secret);
    let mut key_hash = Sha256::digest(&key_input).to_vec();
    if key_hash[0] == 0 {
        key_hash.drain(0..1);
    }

    let counter = time_secs / period;
    let hash = hotp::hmac(
        crate::otp::types::HashAlgorithm::Sha256,
        &key_hash,
        &counter.to_be_bytes(),
    )?;
    let code = hotp::truncate8(&hash);

    let digits = if digits == 0 { 8 } else { digits };
    let modulus = 26u64
        .checked_pow(digits)
        .ok_or(Error::InvalidDigits(digits))?;
    let mut c = code % modulus;
    let mut out = vec![0u8; digits as usize];
    for i in (0..digits as usize).rev() {
        out[i] = b'a' + (c % 26) as u8;
        c /= 26;
    }
    Ok(String::from_utf8(out).expect("lowercase alphabet is ASCII"))
}

/// Validates a Yandex secret and returns it truncated to 16 bytes.
pub fn normalize_secret(secret: &[u8]) -> Result<Vec<u8>> {
    match secret.len() {
        SECRET_LENGTH => Ok(secret.to_vec()),
        SECRET_FULL_LENGTH => {
            if !checksum_valid(secret) {
                return Err(Error::InvalidYandexChecksum);
            }
            Ok(secret[..SECRET_LENGTH].to_vec())
        }
        len => Err(Error::InvalidSecretLength(len)),
    }
}

/// Validates the 12-bit checksum embedded in a 26-byte Yandex secret.
///
/// Independent implementation of the publicly described algorithm (originally
/// reverse-engineered for KeeYaOtp and mirrored by Aegis). No code is copied.
pub fn checksum_valid(secret: &[u8]) -> bool {
    let len = secret.len();
    if len != SECRET_FULL_LENGTH {
        return false;
    }
    let original = (u16::from(secret[len - 2] & 0x0F) << 8) | u16::from(secret[len - 1]);

    let mut accum: u16 = 0;
    let mut accum_bits: u32 = 0;
    let mut total_bits = (len * 8) as i32 - 12;
    let mut input_index = 0usize;
    let mut input_bits: u32 = 8;

    while total_bits > 0 {
        let mut required = (13 - accum_bits as i32).max(0);
        if total_bits < required {
            required = total_bits;
        }
        while required > 0 {
            let mask = (1u32 << input_bits) - 1;
            let mut cur = (secret[input_index] as u32) & mask;
            let bits_to_read = required.min(input_bits as i32);
            cur >>= input_bits - bits_to_read as u32;
            accum = (accum << bits_to_read) | cur as u16;
            total_bits -= bits_to_read;
            required -= bits_to_read;
            input_bits -= bits_to_read as u32;
            accum_bits += bits_to_read as u32;
            if input_bits == 0 {
                input_index += 1;
                input_bits = 8;
            }
        }
        if accum_bits == 13 {
            // CRC-ish mask used by Yandex.
            accum ^= 0b1_1000_1111_0011u16;
        }
        accum_bits = 16 - accum.leading_zeros();
    }

    accum == original
}

/// Computes the checksum that [checksum_valid] expects, given the first 24
/// payload bytes (the last two bytes' value is replaced).
///
/// Useful for tests and for generating valid secrets.
pub fn checksum_compute(payload24: &[u8]) -> u16 {
    assert_eq!(payload24.len(), 24);
    let mut secret = [0u8; SECRET_FULL_LENGTH];
    secret[..24].copy_from_slice(payload24);
    // Run the validator's loop over all but the last 12 bits; the high nibble
    // of byte 24 is payload, low nibble + byte 25 are the checksum.
    let mut accum: u16 = 0;
    let mut accum_bits: u32 = 0;
    let mut total_bits = (SECRET_FULL_LENGTH * 8) as i32 - 12;
    let mut input_index = 0usize;
    let mut input_bits: u32 = 8;
    while total_bits > 0 {
        let mut required = (13 - accum_bits as i32).max(0);
        if total_bits < required {
            required = total_bits;
        }
        while required > 0 {
            let mask = (1u32 << input_bits) - 1;
            let mut cur = (secret[input_index] as u32) & mask;
            let bits_to_read = required.min(input_bits as i32);
            cur >>= input_bits - bits_to_read as u32;
            accum = (accum << bits_to_read) | cur as u16;
            total_bits -= bits_to_read;
            required -= bits_to_read;
            input_bits -= bits_to_read as u32;
            accum_bits += bits_to_read as u32;
            if input_bits == 0 {
                input_index += 1;
                input_bits = 8;
            }
        }
        if accum_bits == 13 {
            accum ^= 0b1_1000_1111_0011u16;
        }
        accum_bits = 16 - accum.leading_zeros();
    }
    accum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn sixteen_byte_secret_passes() {
        let secret = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(normalize_secret(&secret).unwrap(), secret);
    }

    #[test]
    fn twenty_six_byte_secret_roundtrip() {
        // Build a valid 26-byte secret: 24 payload bytes, high nibble of byte
        // 24 is payload, low nibble + byte 25 are the checksum.
        let mut payload = [0u8; 24];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        let checksum = checksum_compute(&payload);

        let mut full = [0u8; SECRET_FULL_LENGTH];
        full[..24].copy_from_slice(&payload);
        full[24] = (full[24] & 0xF0) | ((checksum >> 8) as u8 & 0x0F);
        full[25] = (checksum & 0xFF) as u8;

        assert!(checksum_valid(&full));
        let normalized = normalize_secret(&full).unwrap();
        assert_eq!(normalized, payload[..16]);
    }

    #[test]
    fn corrupt_checksum_rejected() {
        let mut payload = [0u8; 24];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        let checksum = checksum_compute(&payload);
        let mut full = [0u8; SECRET_FULL_LENGTH];
        full[..24].copy_from_slice(&payload);
        full[24] = (full[24] & 0xF0) | ((checksum >> 8) as u8 & 0x0F);
        full[25] = (checksum & 0xFF) as u8;
        full[25] ^= 0x01; // corrupt

        assert!(!checksum_valid(&full));
        assert!(normalize_secret(&full).is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(normalize_secret(&[0u8; 15]).is_err());
        assert!(normalize_secret(&[0u8; 27]).is_err());
    }

    #[test]
    fn deterministic() {
        let secret = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let a = yandex(&secret, "1234", 30, 8, 1_700_000_000).unwrap();
        let b = yandex(&secret, "1234", 30, 8, 1_700_000_000).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|c| c.is_ascii_lowercase()));
    }
}
