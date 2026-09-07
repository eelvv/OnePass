//! KeePass Argon2 KDF (Argon2d / Argon2id).
//!
//! KeePass stores the memory cost in bytes; the Argon2 reference (and this
//! module) use KiB, so the caller divides bytes by 1024. Secret key and
//! associated data are not used by KeePass (empty).

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};

/// Argon2 variants. KeePass KDBX uses Argon2d (and Argon2id in newer files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Kind {
    Argon2d,
    Argon2id,
    Argon2i,
}

/// Derives a 32-byte key from `composite_key` with Argon2.
///
/// - `memory_kib`: m_cost in KiB (KeePass stores bytes; divide by 1024)
/// - `iterations`: t_cost
/// - `parallelism`: p_cost
/// - `version`: Argon2 version (0x10 or 0x13)
pub fn transform_argon2(
    kind: Argon2Kind,
    composite_key: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    version: u32,
) -> Result<[u8; 32]> {
    let algorithm = match kind {
        Argon2Kind::Argon2d => Algorithm::Argon2d,
        Argon2Kind::Argon2id => Algorithm::Argon2id,
        Argon2Kind::Argon2i => Algorithm::Argon2i,
    };
    let version = match version {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        v => return Err(Error::Kdf(format!("unsupported argon2 version 0x{v:x}"))),
    };
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(algorithm, version, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(composite_key, salt, &mut out)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_length() {
        let out = transform_argon2(
            Argon2Kind::Argon2d,
            b"password",
            b"saltsaltsaltsalt",
            65536,
            2,
            2,
            0x13,
        )
        .unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(
            out,
            transform_argon2(
                Argon2Kind::Argon2d,
                b"password",
                b"saltsaltsaltsalt",
                65536,
                2,
                2,
                0x13,
            )
            .unwrap()
        );
    }

    #[test]
    fn bad_version_rejected() {
        assert!(transform_argon2(
            Argon2Kind::Argon2d,
            b"password",
            b"saltsaltsaltsalt",
            65536,
            2,
            2,
            0x99,
        )
        .is_err());
    }
}
