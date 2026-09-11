//! KeePass AES-KDF.
//!
//! Reference algorithm (KeePass 2.x / KeePassDX): the 32-byte composite key is
//! encrypted `rounds` times with AES-256 in ECB mode (key = 32-byte transform
//! seed). If the seed or key is not exactly 32 bytes it is first hashed with
//! SHA-256.
//!
//! The ECB result **is** the transformed key — no extra hash here. The single
//! SHA-256 that finalizes the chain happens once at the master-seed mixing
//! stage (`keys::final_key` = SHA-256(master_seed || transformed_key)), which
//! is shared by the AES-KDF and Argon2 paths alike.

use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Normalizes input to 32 bytes: used as-is when exactly 32 bytes, otherwise
/// SHA-256 hashed (matching KeePass).
fn normalize32(data: &[u8]) -> [u8; 32] {
    if data.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(data);
        out
    } else {
        Sha256::digest(data).into()
    }
}

/// Transforms a composite key using the KeePass AES-KDF.
///
/// - `seed`: 32-byte transform seed (else SHA-256 hashed first)
/// - `composite_key`: 32-byte composite key (else SHA-256 hashed first)
/// - `rounds`: number of AES-256-ECB iterations (>= 1)
///
/// Returns the raw 32-byte transformed key. It is *not* hashed here: the
/// chain-level SHA-256 (`keys::final_key`) is the one hash KeePass applies,
/// and adding another one would make every AES-KDF vault undecryptable.
pub fn transform_aes_kdf(seed: &[u8], composite_key: &[u8], rounds: u64) -> Result<[u8; 32]> {
    let seed32 = normalize32(seed);
    let mut key = normalize32(composite_key);

    let cipher = Aes256::new_from_slice(&seed32).map_err(|_| Error::InvalidSecret)?;
    for _ in 0..rounds {
        for i in (0..32).step_by(16) {
            let mut block = Block::<Aes256>::clone_from_slice(&key[i..i + 16]);
            cipher.encrypt_block(&mut block);
            key[i..i + 16].copy_from_slice(&block);
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn deterministic_and_length() {
        let seed = [7u8; 32];
        let key = [9u8; 32];
        let a = transform_aes_kdf(&seed, &key, 6000).unwrap();
        let b = transform_aes_kdf(&seed, &key, 6000).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn short_key_is_hashed_first() {
        let seed = [0u8; 32];
        // 5-byte key -> SHA-256("short") then transformed
        let out = transform_aes_kdf(&seed, b"short", 1).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(out, transform_aes_kdf(&seed, b"short", 1).unwrap());
        assert_eq!(
            hex::encode(&out),
            hex::encode(&transform_aes_kdf(&seed, &Sha256::digest(b"short"), 1).unwrap())
        );
    }
}
