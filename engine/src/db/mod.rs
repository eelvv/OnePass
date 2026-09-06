//! KeePass KDBX database format (header, keys, XML, streams).

pub mod compress;
pub mod header;
pub mod inner_header;
pub mod kdf_params;
pub mod keys;
pub mod otp;
pub mod stream;
pub mod transfer;
pub mod variant_dict;
pub mod vault;
pub mod xml;

pub use header::{Compression, KdbxHeader};
pub use inner_header::InnerHeader;
pub use kdf_params::{Argon2Variant, KdfParams};
pub use otp::{entry_otp, entry_otp_code, set_entry_otp};
pub use stream::protected::{ProtectedStream, ProtectedStreamKind};
pub use transfer::{
    entry_from_otp_params, entry_from_otpauth_uri, export_aegis_json, export_google_migration,
    export_otpauth_uris, import_aegis_json, import_google_migration, import_otpauth_uris,
    otp_entries,
};
pub use vault::{open, save};
pub use xml::{Entry, Field, Group, Vault};

/// Fills `len` bytes with cryptographically secure randomness.
pub fn random_bytes(len: usize) -> crate::error::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)
        .map_err(|e| crate::error::Error::Encoding(format!("getrandom: {e}")))?;
    Ok(buf)
}
