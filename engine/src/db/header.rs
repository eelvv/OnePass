//! KDBX outer header parsing and serialization.
//!
//! Layout (KeePass 2.x): signature (2×u32 LE), version (u32 LE), then a
//! sequence of TLV fields until an `EndOfHeader` (0x00) terminator. Field
//! length is 2 bytes for KDBX 3.1 and 4 bytes for KDBX 4.x.

use crate::cipher::CipherAlgorithm;
use crate::db::kdf_params::KdfParams;
use crate::db::variant_dict::VariantDictionary;
use crate::error::{Error, Result};

pub const SIG1: u32 = 0x9AA2_D903;
pub const SIG2: u32 = 0xB54B_FB67;
pub const SIG2_PRE: u32 = 0xB54B_FB66;

pub const VERSION_31: u32 = 0x0003_0001;
pub const VERSION_40: u32 = 0x0004_0000;
pub const VERSION_41: u32 = 0x0004_0001;

const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF_0000;

// Header field IDs.
const FIELD_END: u8 = 0;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_TRANSFORM_SEED: u8 = 5;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_INNER_STREAM_KEY: u8 = 8;
const FIELD_STREAM_START_BYTES: u8 = 9;
const FIELD_INNER_STREAM_ID: u8 = 10;
const FIELD_KDF_PARAMS: u8 = 11;
const FIELD_PUBLIC_CUSTOM_DATA: u8 = 12;

/// Compression algorithm for the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

impl Compression {
    pub fn from_flag(flag: u32) -> Option<Self> {
        match flag {
            0 => Some(Self::None),
            1 => Some(Self::Gzip),
            _ => None,
        }
    }

    pub fn flag(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
        }
    }
}

/// Parsed KDBX outer header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdbxHeader {
    pub version: u32,
    pub cipher: CipherAlgorithm,
    pub compression: Compression,
    pub master_seed: [u8; 32],
    pub encryption_iv: Vec<u8>,
    pub stream_start_bytes: [u8; 32],
    pub kdf: KdfParams,
    pub public_custom_data: VariantDictionary,
    /// v3-only (KDBX 4 stores these in the inner header inside the XML).
    pub inner_random_stream_id: Option<u32>,
    pub inner_random_stream_key: Option<[u8; 32]>,
}

impl KdbxHeader {
    /// Parses the outer header from the start of a KDBX file.
    ///
    /// Returns the header and the number of bytes consumed (the encrypted
    /// content starts at that offset).
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let mut pos = 0usize;

        let sig1 = read_u32(data, &mut pos)?;
        let sig2 = read_u32(data, &mut pos)?;
        if sig1 != SIG1 || (sig2 != SIG2 && sig2 != SIG2_PRE) {
            return Err(Error::Encoding(
                "not a KDBX file (bad signature)".to_string(),
            ));
        }

        let version = read_u32(data, &mut pos)?;
        if !valid_version(version) {
            return Err(Error::Encoding(format!(
                "unsupported KDBX version 0x{version:08x}"
            )));
        }

        let mut header = KdbxHeader {
            version,
            cipher: CipherAlgorithm::Aes256Cbc,
            compression: Compression::None,
            master_seed: [0u8; 32],
            encryption_iv: Vec::new(),
            stream_start_bytes: [0u8; 32],
            kdf: KdfParams::Aes {
                rounds: 0,
                seed: [0u8; 32],
            },
            public_custom_data: VariantDictionary::new(),
            inner_random_stream_id: None,
            inner_random_stream_key: None,
        };

        let mut transform_seed = [0u8; 32];
        let mut transform_rounds: u64 = 0;

        loop {
            let field_id = read_u8(data, &mut pos)?;
            let field_size = if version < VERSION_40 {
                read_u16(data, &mut pos)? as usize
            } else {
                read_u32(data, &mut pos)? as usize
            };
            // KeePass writes the EndOfHeader field with 4 bytes of data
            // ("\r\n\r\n"), so consume the field data for every field first.
            let field_data = read_bytes(data, &mut pos, field_size)?.to_vec();
            if field_id == FIELD_END {
                break;
            }

            match field_id {
                FIELD_CIPHER_ID => {
                    header.cipher = CipherAlgorithm::from_uuid(&field_data)?;
                }
                FIELD_COMPRESSION => {
                    let flag = read_u32_slice(&field_data)?;
                    header.compression = Compression::from_flag(flag).ok_or_else(|| {
                        Error::Encoding(format!("unknown compression flag {flag}"))
                    })?;
                }
                FIELD_MASTER_SEED => header.master_seed = fixed32(&field_data, "master seed")?,
                FIELD_TRANSFORM_SEED => transform_seed = fixed32(&field_data, "transform seed")?,
                FIELD_TRANSFORM_ROUNDS => {
                    transform_rounds = read_u64_slice(&field_data)?;
                }
                FIELD_ENCRYPTION_IV => header.encryption_iv = field_data,
                FIELD_INNER_STREAM_KEY => {
                    header.inner_random_stream_key =
                        Some(fixed32(&field_data, "inner stream key")?);
                }
                FIELD_STREAM_START_BYTES => {
                    header.stream_start_bytes = fixed32(&field_data, "stream start bytes")?;
                }
                FIELD_INNER_STREAM_ID => {
                    header.inner_random_stream_id = Some(read_u32_slice(&field_data)?);
                }
                FIELD_KDF_PARAMS => {
                    header.kdf =
                        KdfParams::from_dict(&VariantDictionary::deserialize(&field_data)?)?;
                }
                FIELD_PUBLIC_CUSTOM_DATA => {
                    header.public_custom_data = VariantDictionary::deserialize(&field_data)?;
                }
                _ => {
                    // Comment (1) and unknown fields are ignored.
                }
            }
        }

        // KDBX 3.1 derives AES-KDF params from the separate fields.
        if version < VERSION_40 {
            header.kdf = KdfParams::Aes {
                rounds: transform_rounds,
                seed: transform_seed,
            };
        }

        Ok((header, pos))
    }

    /// Serializes the header (KDBX 4 field layout).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIG1.to_le_bytes());
        out.extend_from_slice(&SIG2.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());

        // CipherID (2)
        push_field(&mut out, FIELD_CIPHER_ID, &self.cipher.uuid(), self.version);
        // CompressionFlags (3)
        push_field(
            &mut out,
            FIELD_COMPRESSION,
            &self.compression.flag().to_le_bytes(),
            self.version,
        );
        // MasterSeed (4)
        push_field(&mut out, FIELD_MASTER_SEED, &self.master_seed, self.version);
        // EncryptionIV (7)
        push_field(
            &mut out,
            FIELD_ENCRYPTION_IV,
            &self.encryption_iv,
            self.version,
        );
        // KdfParameters (11)
        push_field(
            &mut out,
            FIELD_KDF_PARAMS,
            &self.kdf.to_dict().serialize(),
            self.version,
        );
        // PublicCustomData (12)
        if !self.public_custom_data.serialize().is_empty() {
            push_field(
                &mut out,
                FIELD_PUBLIC_CUSTOM_DATA,
                &self.public_custom_data.serialize(),
                self.version,
            );
        }
        // StreamStartBytes (9) — KDBX 3.1 only.
        if self.version < VERSION_40 {
            push_field(
                &mut out,
                FIELD_STREAM_START_BYTES,
                &self.stream_start_bytes,
                self.version,
            );
        }
        // EndOfHeader (0) — KeePass writes "\r\n\r\n" as the field data.
        out.push(FIELD_END);
        push_size(&mut out, 4, self.version);
        out.extend_from_slice(b"\r\n\r\n");

        out
    }
}

fn valid_version(version: u32) -> bool {
    version & FILE_VERSION_CRITICAL_MASK <= VERSION_40 & FILE_VERSION_CRITICAL_MASK
}

fn push_field(out: &mut Vec<u8>, id: u8, value: &[u8], version: u32) {
    out.push(id);
    push_size(out, value.len(), version);
    out.extend_from_slice(value);
}

fn push_size(out: &mut Vec<u8>, size: usize, version: u32) {
    if version < VERSION_40 {
        out.extend_from_slice(&(size as u16).to_le_bytes());
    } else {
        out.extend_from_slice(&(size as u32).to_le_bytes());
    }
}

fn fixed32(data: &[u8], what: &str) -> Result<[u8; 32]> {
    data.try_into()
        .map_err(|_| Error::Encoding(format!("{what} must be 32 bytes")))
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *data
        .get(*pos)
        .ok_or_else(|| Error::Encoding("truncated header".to_string()))?;
    *pos += 1;
    Ok(b)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    let b = read_bytes(data, pos, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    let b = read_bytes(data, pos, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u32_slice(data: &[u8]) -> Result<u32> {
    let b: [u8; 4] = data
        .try_into()
        .map_err(|_| Error::Encoding("expected 4 bytes".to_string()))?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_slice(data: &[u8]) -> Result<u64> {
    let b: [u8; 8] = data
        .try_into()
        .map_err(|_| Error::Encoding("expected 8 bytes".to_string()))?;
    Ok(u64::from_le_bytes(b))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *pos + len > data.len() {
        return Err(Error::Encoding("truncated header".to_string()));
    }
    let s = &data[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::kdf_params::Argon2Variant;

    fn sample_header() -> KdbxHeader {
        KdbxHeader {
            version: VERSION_40,
            cipher: CipherAlgorithm::Aes256Cbc,
            compression: Compression::Gzip,
            master_seed: [0x01; 32],
            encryption_iv: vec![0x02; 16],
            // StreamStartBytes is a 3.1-only field; KDBX 4 stores it as zeros.
            stream_start_bytes: [0u8; 32],
            kdf: KdfParams::Argon2 {
                id: Argon2Variant::Argon2d,
                salt: [0x04; 32],
                parallelism: 4,
                memory: 64 * 1024 * 1024,
                iterations: 3,
                version: 0x13,
            },
            public_custom_data: VariantDictionary::new(),
            inner_random_stream_id: None,
            inner_random_stream_key: None,
        }
    }

    #[test]
    fn v4_roundtrip() {
        let h = sample_header();
        let ser = h.serialize();
        let (parsed, consumed) = KdbxHeader::parse(&ser).unwrap();
        assert_eq!(consumed, ser.len());
        assert_eq!(parsed, h);
    }

    #[test]
    fn v4_with_aes_kdf_roundtrip() {
        let mut h = sample_header();
        h.kdf = KdfParams::Aes {
            rounds: 600_000,
            seed: [0xAB; 32],
        };
        let ser = h.serialize();
        let (parsed, _) = KdbxHeader::parse(&ser).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut ser = sample_header().serialize();
        ser[0] ^= 0xFF;
        assert!(KdbxHeader::parse(&ser).is_err());
    }

    #[test]
    fn golden_v4_header() {
        // Hand-verified byte layout for a minimal KDBX 4.0 header.
        let mut expected = Vec::new();
        expected.extend_from_slice(&SIG1.to_le_bytes());
        expected.extend_from_slice(&SIG2.to_le_bytes());
        expected.extend_from_slice(&VERSION_40.to_le_bytes());
        // CipherID (AES) field
        expected.push(FIELD_CIPHER_ID);
        expected.extend_from_slice(&16u32.to_le_bytes());
        expected.extend_from_slice(&CipherAlgorithm::Aes256Cbc.uuid());
        // Compression field (None = 0)
        expected.push(FIELD_COMPRESSION);
        expected.extend_from_slice(&4u32.to_le_bytes());
        expected.extend_from_slice(&0u32.to_le_bytes());
        // EndOfHeader
        expected.push(FIELD_END);
        expected.extend_from_slice(&4u32.to_le_bytes());
        expected.extend_from_slice(b"\r\n\r\n");

        let (parsed, consumed) = KdbxHeader::parse(&expected).unwrap();
        assert_eq!(consumed, expected.len());
        assert_eq!(parsed.version, VERSION_40);
        assert_eq!(parsed.cipher, CipherAlgorithm::Aes256Cbc);
        assert_eq!(parsed.compression, Compression::None);
    }
}
