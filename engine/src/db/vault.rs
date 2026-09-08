//! High-level KDBX vault open: full decryption chain → structured [`Vault`].

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::cipher::CipherAlgorithm;
use crate::db::compress::{gzip_compress, gzip_decompress};
use crate::db::header::{VERSION_40, VERSION_41};
use crate::db::stream::{hashed_block, hmac_block};
use crate::db::variant_dict::VariantDictionary;
use crate::db::{keys, xml};
use crate::db::{
    Argon2Variant, Compression, InnerHeader, KdbxHeader, KdfParams, ProtectedStream,
    ProtectedStreamKind, Vault,
};
use crate::error::{Error, Result};
use crate::kdf::{transform_aes_kdf, transform_argon2, Argon2Kind};
use zeroize::Zeroizing;

/// Opens (decrypts and parses) a KDBX file with the given password.
///
/// Intermediate key material is zeroized when the call returns.
pub fn open(data: &[u8], password: &[u8]) -> Result<Vault> {
    let (header, header_len) = KdbxHeader::parse(data).map_err(|e| Error::Format(e.to_string()))?;
    let header_bytes = &data[..header_len];

    let composite = Zeroizing::new(keys::composite_key(&[&*Zeroizing::new(
        keys::password_key(password),
    )]));
    let transformed = Zeroizing::new(transform(&header, &composite)?);
    let final_key = Zeroizing::new(keys::final_key(&header.master_seed, &transformed));
    let hmac_key = Zeroizing::new(keys::hmac_key(&header.master_seed, &transformed));

    let ciphertext = if header.version >= VERSION_40 {
        verify_header_auth(data, header_len, header_bytes, &hmac_key)?;
        hmac_block::decode(&data[header_len + 64..], &hmac_key)?
    } else {
        hashed_block::decode(&data[header_len..])?
    };

    let compressed = header
        .cipher
        .decrypt(&final_key[..], &header.encryption_iv, &ciphertext)
        .map_err(|_| {
            // KDBX 4 authenticated the ciphertext with per-block HMACs, so a
            // decrypt failure here means the file is corrupted. KDBX 3 has no
            // block auth; a padding failure is the wrong-password signal.
            if header.version >= VERSION_40 {
                Error::Format("payload decrypt failed".to_string())
            } else {
                Error::WrongPassword
            }
        })?;
    let payload = match header.compression {
        Compression::Gzip => {
            gzip_decompress(&compressed).map_err(|e| Error::Format(e.to_string()))?
        }
        Compression::None => compressed,
    };

    let (xml_bytes, mut stream) = if header.version >= VERSION_40 {
        let (inner, xml_offset) =
            InnerHeader::parse(&payload).map_err(|e| Error::Format(e.to_string()))?;
        let kind = match inner.inner_random_stream_id {
            2 => ProtectedStreamKind::Salsa20,
            _ => ProtectedStreamKind::ChaCha20,
        };
        let stream = ProtectedStream::new(kind, &inner.inner_random_stream_key);
        (&payload[xml_offset..], stream)
    } else {
        let kind = match header.inner_random_stream_id {
            Some(2) => ProtectedStreamKind::Salsa20,
            _ => ProtectedStreamKind::ChaCha20,
        };
        let key = header.inner_random_stream_key.unwrap_or([0u8; 32]);
        let stream = ProtectedStream::new(kind, &key);
        (&payload[..], stream)
    };

    xml::parse(xml_bytes, &mut stream).map_err(|e| Error::Format(e.to_string()))
}

/// Tunables for [`save_with`]. Random salts, seeds, and IVs are always
/// generated fresh; these knobs only pin the KDF work factors.
#[derive(Debug, Clone, Copy)]
pub struct SaveOptions {
    /// Argon2 memory cost in bytes (default 64 MiB).
    pub argon2_memory: u64,
    /// Argon2 passes (default 3).
    pub argon2_iterations: u64,
    /// Argon2 lanes (default 2).
    pub argon2_parallelism: u32,
}

impl Default for SaveOptions {
    fn default() -> Self {
        Self {
            argon2_memory: 64 * 1024 * 1024,
            argon2_iterations: 3,
            argon2_parallelism: 2,
        }
    }
}

impl SaveOptions {
    /// Lower memory cost tuned for mobile unlock latency (~32 MiB).
    pub fn mobile() -> Self {
        Self {
            argon2_memory: 32 * 1024 * 1024,
            ..Default::default()
        }
    }
}

/// Saves a [`Vault`] as an encrypted KDBX 4 file with the given password.
///
/// Uses Argon2d KDF, AES-256-CBC, GZip, and a ChaCha20 inner random stream.
pub fn save(vault: &Vault, password: &[u8]) -> Result<Vec<u8>> {
    save_with(vault, password, &SaveOptions::default())
}

/// [`save`] with explicit KDF work-factor options.
pub fn save_with(vault: &Vault, password: &[u8], options: &SaveOptions) -> Result<Vec<u8>> {
    // --- generate random parameters --------------------------------------
    let master_seed = random_bytes(32)?;
    let iv = random_bytes(16)?;
    let salt = random_bytes(32)?;
    let inner_key = random_bytes(64)?;

    let kdf = KdfParams::Argon2 {
        id: Argon2Variant::Argon2d,
        salt: to32(salt)?,
        parallelism: options.argon2_parallelism,
        memory: options.argon2_memory,
        iterations: options.argon2_iterations,
        version: 0x13,
    };

    let header = KdbxHeader {
        version: VERSION_41,
        cipher: CipherAlgorithm::Aes256Cbc,
        compression: Compression::Gzip,
        master_seed: to32(master_seed)?,
        encryption_iv: iv,
        stream_start_bytes: [0u8; 32],
        kdf,
        public_custom_data: VariantDictionary::new(),
        inner_random_stream_id: None,
        inner_random_stream_key: None,
    };
    let header_bytes = header.serialize();
    let header_hash: [u8; 32] = Sha256::digest(&header_bytes).into();

    // --- serialize XML + inner header ------------------------------------
    let mut stream = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &inner_key);
    let xml_bytes = xml::serialize(vault, &mut stream, &header_hash)?;

    let inner = InnerHeader {
        inner_random_stream_id: 3,
        inner_random_stream_key: inner_key,
        binaries: Vec::new(),
    };
    let mut payload = inner.serialize();
    payload.extend_from_slice(&xml_bytes);

    // --- compress + encrypt + HMAC blocks ---------------------------------
    let compressed = gzip_compress(&payload)?;

    let composite = Zeroizing::new(keys::composite_key(&[&*Zeroizing::new(
        keys::password_key(password),
    )]));
    let transformed = Zeroizing::new(transform(&header, &composite)?);
    let final_key = Zeroizing::new(keys::final_key(&header.master_seed, &transformed));
    let hmac_key = Zeroizing::new(keys::hmac_key(&header.master_seed, &transformed));

    let ciphertext = header
        .cipher
        .encrypt(&final_key[..], &header.encryption_iv, &compressed)?;
    let blocks = hmac_block::encode(&ciphertext, &hmac_key, 1024 * 1024);

    // --- assemble: header || header_hash || header_hmac || blocks ---------
    let header_hmac = compute_header_hmac(&header_bytes, &hmac_key);
    let mut out = header_bytes;
    out.extend_from_slice(&header_hash);
    out.extend_from_slice(&header_hmac);
    out.extend_from_slice(&blocks);
    Ok(out)
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Encoding(format!("getrandom: {e}")))?;
    Ok(buf)
}

fn to32(v: Vec<u8>) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| Error::Encoding("expected 32 bytes".to_string()))
}

fn compute_header_hmac(header_bytes: &[u8], hmac_key: &[u8; 64]) -> [u8; 32] {
    let mut bk = Sha512::new();
    bk.update([0xFFu8; 8]);
    bk.update(hmac_key);
    let block_key = bk.finalize();
    let mut mac = Hmac::<Sha256>::new_from_slice(&block_key).expect("hmac key is valid");
    mac.update(header_bytes);
    mac.finalize().into_bytes().into()
}

fn transform(header: &KdbxHeader, composite: &[u8; 32]) -> Result<[u8; 32]> {
    match &header.kdf {
        KdfParams::Aes { rounds, seed } => transform_aes_kdf(seed, composite, *rounds),
        KdfParams::Argon2 {
            id,
            salt,
            parallelism,
            memory,
            iterations,
            version,
        } => {
            let kind = match id {
                Argon2Variant::Argon2d => Argon2Kind::Argon2d,
                Argon2Variant::Argon2id => Argon2Kind::Argon2id,
            };
            transform_argon2(
                kind,
                composite,
                salt,
                (memory / 1024) as u32,
                *iterations as u32,
                *parallelism,
                *version,
            )
        }
    }
}

/// KDBX 4 verifies a 32-byte SHA-256 of the header bytes and a 32-byte header
/// HMAC (block key = SHA-512(0xFF..FF || hmac_key)) immediately after the
/// header.
fn verify_header_auth(
    data: &[u8],
    header_len: usize,
    header_bytes: &[u8],
    hmac_key: &[u8; 64],
) -> Result<()> {
    if data.len() < header_len + 64 {
        return Err(Error::Encoding("truncated after header".to_string()));
    }
    let stored_hash = &data[header_len..header_len + 32];
    let stored_hmac = &data[header_len + 32..header_len + 64];

    let computed_hash = Sha256::digest(header_bytes);
    if computed_hash.as_slice() != stored_hash {
        return Err(Error::Format("header sha256 mismatch".to_string()));
    }

    if compute_header_hmac(header_bytes, hmac_key) != stored_hmac {
        // The HMAC key derives from the transformed composite key, so a
        // mismatch means the password does not match this vault.
        return Err(Error::WrongPassword);
    }
    Ok(())
}
