//! Symmetric ciphers used by KDBX: AES-256-CBC, Twofish-256-CBC, ChaCha20.

pub mod aes;
pub mod chacha20;
pub mod twofish;

use crate::error::{Error, Result};

/// Encryption algorithms supported by the KeePass database format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    Aes256Cbc,
    Twofish256Cbc,
    ChaCha20,
}

impl CipherAlgorithm {
    /// Key size in bytes (always 256-bit).
    pub fn key_len(&self) -> usize {
        32
    }

    /// IV/nonce size in bytes.
    pub fn iv_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 12,
            _ => 16,
        }
    }

    /// KeePass cipher UUID (in-memory byte order as KeePass defines it).
    pub fn uuid(&self) -> [u8; 16] {
        match self {
            Self::Aes256Cbc => [
                0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC,
                0x5A, 0xFF,
            ],
            Self::Twofish256Cbc => [
                0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65,
                0x34, 0x6C,
            ],
            Self::ChaCha20 => [
                0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB,
                0xB5, 0x9A,
            ],
        }
    }

    /// Resolves a KeePass cipher UUID (16 bytes, in-memory order) to an
    /// algorithm.
    pub fn from_uuid(uuid: &[u8]) -> Result<Self> {
        let uuid: [u8; 16] = uuid
            .try_into()
            .map_err(|_| Error::Encoding("cipher uuid must be 16 bytes".to_string()))?;
        [Self::Aes256Cbc, Self::Twofish256Cbc, Self::ChaCha20]
            .into_iter()
            .find(|a| a.uuid() == uuid)
            .ok_or_else(|| Error::UnsupportedAlgorithm("unknown cipher uuid".to_string()))
    }

    /// Encrypts `plaintext` with `key` (32 bytes) and `iv`.
    pub fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidSecret);
        }
        if iv.len() != self.iv_len() {
            return Err(Error::Encoding("bad iv length".to_string()));
        }
        match self {
            Self::Aes256Cbc => aes::encrypt(key, iv, plaintext),
            Self::Twofish256Cbc => twofish::encrypt(key, iv, plaintext),
            Self::ChaCha20 => chacha20::encrypt(key, iv, plaintext),
        }
    }

    /// Decrypts `ciphertext` with `key` (32 bytes) and `iv`.
    pub fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidSecret);
        }
        if iv.len() != self.iv_len() {
            return Err(Error::Encoding("bad iv length".to_string()));
        }
        match self {
            Self::Aes256Cbc => aes::decrypt(key, iv, ciphertext),
            Self::Twofish256Cbc => twofish::decrypt(key, iv, ciphertext),
            Self::ChaCha20 => chacha20::decrypt(key, iv, ciphertext),
        }
    }
}

/// Constant-time PKCS#7 unpadding: validates every padding byte in one
/// branch-free pass and returns the plaintext length.
///
/// `block-padding`'s `Pkcs7::unpad` short-circuits on the first mismatching
/// byte, leaking padding validity through timing. KDBX 4 authenticates the
/// ciphertext before it is ever decrypted, but the public decrypt API is also
/// callable directly, so the unpad here is hardened.
fn unpad_pkcs7_ct(buf: &[u8], bs: usize) -> Result<usize> {
    let len = buf.len();
    if len == 0 || !len.is_multiple_of(bs) {
        return Err(Error::Encoding("invalid ciphertext length".to_string()));
    }
    let pad = buf[len - 1] as usize;
    // OR-accumulate (byte ^ pad) over the whole trailing block, masked by
    // whether that byte belongs to the padding. Every branch below depends
    // only on the public buffer length, never on plaintext bytes.
    let mut diff: u8 = 0;
    for i in 0..bs {
        let in_pad = ((bs - i) <= pad) as u8;
        diff |= in_pad & (buf[len - bs + i] ^ (pad as u8));
    }
    let valid = (pad >= 1) as u8 & (pad <= bs) as u8 & ((diff == 0) as u8);
    if valid == 0 {
        return Err(Error::Encoding("bad padding".to_string()));
    }
    Ok(len - pad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_roundtrip() {
        for a in [
            CipherAlgorithm::Aes256Cbc,
            CipherAlgorithm::Twofish256Cbc,
            CipherAlgorithm::ChaCha20,
        ] {
            assert_eq!(CipherAlgorithm::from_uuid(&a.uuid()).unwrap(), a);
        }
    }

    #[test]
    fn iv_sizes() {
        assert_eq!(CipherAlgorithm::Aes256Cbc.iv_len(), 16);
        assert_eq!(CipherAlgorithm::Twofish256Cbc.iv_len(), 16);
        assert_eq!(CipherAlgorithm::ChaCha20.iv_len(), 12);
    }
}
