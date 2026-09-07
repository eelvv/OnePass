//! KDBX inner random stream (protected-field XOR stream).
//!
//! KeePass protects selected XML fields (e.g. passwords) by XORing them with
//! a sequential keystream. KDBX 3.1 uses Salsa20; KDBX 4.x uses ChaCha20.
//!
//! - Salsa20: key = SHA-256(protected_stream_key), fixed 8-byte IV
//!   `E8 30 09 4B 97 20 5D 2A`.
//! - ChaCha20: key = SHA-512(key)[0..32], nonce = SHA-512(key)[32..44].

use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

/// Salsa20 fixed IV (KeePass).
pub const SALSA20_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

/// Which inner random stream to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedStreamKind {
    /// KDBX 3.1.
    Salsa20,
    /// KDBX 4.x.
    ChaCha20,
}

/// ChaCha20 inner-stream key/nonce derivation.
pub fn chacha20_key_nonce(protected_key: &[u8]) -> ([u8; 32], [u8; 12]) {
    let h = Sha512::digest(protected_key);
    let mut key = [0u8; 32];
    key.copy_from_slice(&h[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&h[32..44]);
    (key, nonce)
}

/// Stateful XOR stream over protected fields. The position advances across
/// calls, matching KeePass' single continuous keystream.
pub struct ProtectedStream {
    kind: ProtectedStreamKind,
    key: [u8; 32],
    nonce: [u8; 12],
    position: u64,
}

impl ProtectedStream {
    pub fn new(kind: ProtectedStreamKind, protected_key: &[u8]) -> Self {
        match kind {
            ProtectedStreamKind::ChaCha20 => {
                let (key, nonce) = chacha20_key_nonce(protected_key);
                Self {
                    kind,
                    key,
                    nonce,
                    position: 0,
                }
            }
            ProtectedStreamKind::Salsa20 => {
                let key = Sha256::digest(protected_key).into();
                let mut nonce = [0u8; 12];
                nonce[..8].copy_from_slice(&SALSA20_IV);
                Self {
                    kind,
                    key,
                    nonce,
                    position: 0,
                }
            }
        }
    }

    /// XORs `data` with the keystream at the current position and advances it.
    pub fn xor_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        match self.kind {
            ProtectedStreamKind::ChaCha20 => {
                let mut c = ChaCha20::new_from_slices(&self.key, &self.nonce)
                    .map_err(|_| Error::InvalidSecret)?;
                c.seek(self.position);
                c.apply_keystream(data);
            }
            ProtectedStreamKind::Salsa20 => {
                let mut c = Salsa20::new_from_slices(&self.key, &self.nonce[..8])
                    .map_err(|_| Error::InvalidSecret)?;
                c.seek(self.position);
                c.apply_keystream(data);
            }
        }
        self.position += data.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn chacha20_key_nonce_python() {
        let protected_key: Vec<u8> = (0u8..32).collect();
        let (key, nonce) = chacha20_key_nonce(&protected_key);
        assert_eq!(
            hex::encode(&key),
            "3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f"
        );
        assert_eq!(hex::encode(&nonce), "a9d71862a3e5746b571be3d1");
    }

    #[test]
    fn roundtrip_chacha20() {
        let protected_key = [0x42u8; 32];
        let mut enc = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &protected_key);
        let mut fields = vec![b"password-1".to_vec(), b"password-2".to_vec()];
        for f in &mut fields {
            enc.xor_in_place(f).unwrap();
        }

        let mut dec = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &protected_key);
        for f in &mut fields {
            dec.xor_in_place(f).unwrap();
        }
        assert_eq!(fields[0], b"password-1");
        assert_eq!(fields[1], b"password-2");
    }

    #[test]
    fn roundtrip_salsa20() {
        let protected_key = [0x42u8; 32];
        let mut enc = ProtectedStream::new(ProtectedStreamKind::Salsa20, &protected_key);
        let mut field = b"salsa20 protected".to_vec();
        enc.xor_in_place(&mut field).unwrap();

        let mut dec = ProtectedStream::new(ProtectedStreamKind::Salsa20, &protected_key);
        dec.xor_in_place(&mut field).unwrap();
        assert_eq!(field, b"salsa20 protected");
    }

    #[test]
    fn stream_position_advances() {
        // Two fields XORed in sequence must not reuse keystream.
        let protected_key = [0x07u8; 32];
        let mut enc = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &protected_key);
        let mut a = b"aaaaaaaa".to_vec();
        let mut b = b"bbbbbbbb".to_vec();
        enc.xor_in_place(&mut a).unwrap();
        enc.xor_in_place(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
