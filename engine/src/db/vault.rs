//! High-level KDBX vault open: full decryption chain → structured [`Vault`].

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::db::compress::gzip_decompress;
use crate::db::header::VERSION_40;
use crate::db::stream::{hashed_block, hmac_block};
use crate::db::xml;
use crate::db::{
    keys, Argon2Variant, Compression, InnerHeader, KdbxHeader, KdfParams, ProtectedStream,
    ProtectedStreamKind, Vault,
};
use crate::error::{Error, Result};
use crate::kdf::{transform_aes_kdf, transform_argon2, Argon2Kind};

/// Opens (decrypts and parses) a KDBX file with the given password.
pub fn open(data: &[u8], password: &[u8]) -> Result<Vault> {
    let (header, header_len) = KdbxHeader::parse(data)?;
    let header_bytes = &data[..header_len];

    let composite = keys::composite_key(&[&keys::password_key(password)]);
    let transformed = transform(&header, &composite)?;
    let final_key = keys::final_key(&header.master_seed, &transformed);
    let hmac_key = keys::hmac_key(&header.master_seed, &transformed);

    let ciphertext = if header.version >= VERSION_40 {
        verify_header_auth(data, header_len, header_bytes, &hmac_key)?;
        hmac_block::decode(&data[header_len + 64..], &hmac_key)?
    } else {
        hashed_block::decode(&data[header_len..])?
    };

    let compressed = header
        .cipher
        .decrypt(&final_key, &header.encryption_iv, &ciphertext)?;
    let payload = match header.compression {
        Compression::Gzip => gzip_decompress(&compressed)?,
        Compression::None => compressed,
    };

    let (xml_bytes, mut stream) = if header.version >= VERSION_40 {
        let (inner, xml_offset) = InnerHeader::parse(&payload)?;
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

    xml::parse(xml_bytes, &mut stream)
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
        return Err(Error::Encoding("header sha256 mismatch".to_string()));
    }

    let mut bk = Sha512::new();
    bk.update([0xFFu8; 8]);
    bk.update(hmac_key);
    let block_key = bk.finalize();
    let mut mac = Hmac::<Sha256>::new_from_slice(&block_key).map_err(|_| Error::InvalidSecret)?;
    mac.update(header_bytes);
    if mac.finalize().into_bytes().as_slice() != stored_hmac {
        return Err(Error::Encoding("header hmac mismatch".to_string()));
    }
    Ok(())
}
