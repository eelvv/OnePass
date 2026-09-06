//! Typed KDF parameters ↔ KeePass VariantDictionary (KDBX header field 11).

use crate::db::variant_dict::{VariantDictionary, VdValue};
use crate::error::{Error, Result};

const KEY_UUID: &str = "$UUID";

// KDF UUIDs (16 bytes, KeePass in-memory order).
const AES_UUID: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
const ARGON2D_UUID: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
const ARGON2ID_UUID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

/// Key derivation parameters (mapped to the KeePass KDF VariantDictionary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    /// KeePass AES-KDF.
    Aes {
        /// Transform rounds (param `R`).
        rounds: u64,
        /// Transform seed (param `S`).
        seed: [u8; 32],
    },
    /// KeePass Argon2d / Argon2id.
    Argon2 {
        /// Which Argon2 variant.
        id: Argon2Variant,
        /// Salt (param `S`).
        salt: [u8; 32],
        /// Parallelism (param `P`, u32).
        parallelism: u32,
        /// Memory in bytes (param `M`, u64).
        memory: u64,
        /// Iterations (param `I`, u64).
        iterations: u64,
        /// Argon2 version (param `V`, u32; 0x10 or 0x13).
        version: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d,
    Argon2id,
}

impl KdfParams {
    /// Serializes to a KeePass VariantDictionary.
    pub fn to_dict(&self) -> VariantDictionary {
        let mut d = VariantDictionary::new();
        match self {
            KdfParams::Aes { rounds, seed } => {
                d.set(KEY_UUID, VdValue::ByteArray(AES_UUID.to_vec()));
                d.set("R", VdValue::UInt64(*rounds));
                d.set("S", VdValue::ByteArray(seed.to_vec()));
            }
            KdfParams::Argon2 {
                id,
                salt,
                parallelism,
                memory,
                iterations,
                version,
            } => {
                let uuid = match id {
                    Argon2Variant::Argon2d => ARGON2D_UUID,
                    Argon2Variant::Argon2id => ARGON2ID_UUID,
                };
                d.set(KEY_UUID, VdValue::ByteArray(uuid.to_vec()));
                d.set("S", VdValue::ByteArray(salt.to_vec()));
                d.set("P", VdValue::UInt32(*parallelism));
                d.set("M", VdValue::UInt64(*memory));
                d.set("I", VdValue::UInt64(*iterations));
                d.set("V", VdValue::UInt32(*version));
            }
        }
        d
    }

    /// Parses from a KeePass VariantDictionary.
    pub fn from_dict(d: &VariantDictionary) -> Result<Self> {
        let uuid = d
            .get_byte_array(KEY_UUID)
            .ok_or_else(|| Error::Kdf("missing KDF $UUID".to_string()))?;
        match uuid {
            u if u == AES_UUID => {
                let rounds = d
                    .get_u64("R")
                    .ok_or_else(|| Error::Kdf("AES-KDF missing rounds".to_string()))?;
                let seed = d
                    .get_byte_array("S")
                    .ok_or_else(|| Error::Kdf("AES-KDF missing seed".to_string()))?;
                let seed: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| Error::Kdf("AES-KDF seed must be 32 bytes".to_string()))?;
                Ok(KdfParams::Aes { rounds, seed })
            }
            u if u == ARGON2D_UUID || u == ARGON2ID_UUID => {
                let id = if u == ARGON2D_UUID {
                    Argon2Variant::Argon2d
                } else {
                    Argon2Variant::Argon2id
                };
                let salt = d
                    .get_byte_array("S")
                    .ok_or_else(|| Error::Kdf("Argon2 missing salt".to_string()))?;
                let salt: [u8; 32] = salt
                    .try_into()
                    .map_err(|_| Error::Kdf("Argon2 salt must be 32 bytes".to_string()))?;
                let parallelism = d
                    .get_u32("P")
                    .ok_or_else(|| Error::Kdf("Argon2 missing parallelism".to_string()))?;
                let memory = d
                    .get_u64("M")
                    .ok_or_else(|| Error::Kdf("Argon2 missing memory".to_string()))?;
                let iterations = d
                    .get_u64("I")
                    .ok_or_else(|| Error::Kdf("Argon2 missing iterations".to_string()))?;
                let version = d
                    .get_u32("V")
                    .ok_or_else(|| Error::Kdf("Argon2 missing version".to_string()))?;
                Ok(KdfParams::Argon2 {
                    id,
                    salt,
                    parallelism,
                    memory,
                    iterations,
                    version,
                })
            }
            _ => Err(Error::Kdf("unknown KDF UUID".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip() {
        let p = KdfParams::Aes {
            rounds: 600_000,
            seed: [0xAB; 32],
        };
        let d = p.to_dict();
        assert_eq!(KdfParams::from_dict(&d).unwrap(), p);
    }

    #[test]
    fn argon2_roundtrip() {
        for id in [Argon2Variant::Argon2d, Argon2Variant::Argon2id] {
            let p = KdfParams::Argon2 {
                id,
                salt: [0x11; 32],
                parallelism: 4,
                memory: 64 * 1024 * 1024,
                iterations: 3,
                version: 0x13,
            };
            let d = p.to_dict();
            assert_eq!(KdfParams::from_dict(&d).unwrap(), p, "{id:?}");
        }
    }
}
