//! KeePass KDBX database format (header, keys, XML, streams).

pub mod compress;
pub mod fields;
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

pub use fields::{NOTES, OTP, PASSWORD, TITLE, URL, USER_NAME};
pub use header::{Compression, KdbxHeader};
pub use inner_header::InnerHeader;
pub use kdf_params::{Argon2Variant, KdfParams};
pub use otp::{entry_otp, entry_otp_code, set_entry_otp};
pub use stream::protected::{ProtectedStream, ProtectedStreamKind};
pub use transfer::{
    detect_and_import, entry_from_otp_params, entry_from_otpauth_uri, export_aegis_json,
    export_google_migration, export_otpauth_uris, import_aegis_json, import_google_migration,
    import_otpauth_uris, otp_entries,
};
pub use vault::{open, save, save_with, SaveOptions};
pub use xml::{Entry, Field, Group, Times, Vault};

/// Fills `len` bytes with cryptographically secure randomness.
pub fn random_bytes(len: usize) -> crate::error::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)
        .map_err(|e| crate::error::Error::Encoding(format!("getrandom: {e}")))?;
    Ok(buf)
}

/// Generates a random password of `len` characters
/// (upper/lower/digit/symbols, rejection-sampled for uniformity).
pub fn generate_password(len: usize) -> crate::error::Result<String> {
    generate_password_with_policy(len, &PasswordPolicy::default())
}

/// Which character sets a generated password draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Include `A-Z`.
    pub upper: bool,
    /// Include `a-z`.
    pub lower: bool,
    /// Include `0-9`.
    pub digits: bool,
    /// Include punctuation/symbols.
    pub symbols: bool,
    /// Exclude visually ambiguous characters (`I O l 0 1 | ' \` " . , ; :`).
    pub exclude_ambiguous: bool,
    /// Guarantee at least one character from every enabled set
    /// (requires `len` >= number of enabled sets).
    pub require_each_set: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each_set: false,
        }
    }
}

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";
/// Characters removed when `exclude_ambiguous` is set.
const AMBIGUOUS: &[u8] = b"IOl01|'`\".,;:";

/// Generates a random password of `len` characters following `policy`,
/// rejection-sampled for uniformity.
pub fn generate_password_with_policy(
    len: usize,
    policy: &PasswordPolicy,
) -> crate::error::Result<String> {
    let sets: Vec<&[u8]> = [
        (policy.upper, UPPER),
        (policy.lower, LOWER),
        (policy.digits, DIGITS),
        (policy.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| set)
    .collect();

    if sets.is_empty() {
        return Err(crate::error::Error::InvalidParameter(
            "password policy enables no character set".to_string(),
        ));
    }

    let charset: Vec<u8> = sets
        .iter()
        .flat_map(|set| set.iter().copied())
        .filter(|c| !policy.exclude_ambiguous || !AMBIGUOUS.contains(c))
        .collect();
    if charset.is_empty() {
        return Err(crate::error::Error::InvalidParameter(
            "password policy leaves an empty character set".to_string(),
        ));
    }
    if policy.require_each_set && len < sets.len() {
        return Err(crate::error::Error::InvalidParameter(format!(
            "length {len} cannot cover {} required character sets",
            sets.len()
        )));
    }

    let mut out: Vec<u8> = Vec::with_capacity(len);

    if policy.require_each_set {
        // One guaranteed character per enabled set (respecting ambiguity
        // exclusion; a set reduced to nothing by it is skipped).
        for set in &sets {
            let pool: Vec<u8> = set
                .iter()
                .copied()
                .filter(|c| !policy.exclude_ambiguous || !AMBIGUOUS.contains(c))
                .collect();
            if let Some(&c) = pool.get(random_index(pool.len())?) {
                out.push(c);
            }
        }
    }
    while out.len() < len {
        out.push(charset[random_index(charset.len())?]);
    }

    // Shuffle so the guaranteed positions are uniform (Fisher-Yates).
    for i in (1..out.len()).rev() {
        let j = random_index(i + 1)?;
        out.swap(i, j);
    }

    Ok(String::from_utf8(out).expect("charset is ASCII"))
}

/// Uniform random index in `0..len` via rejection sampling.
fn random_index(len: usize) -> crate::error::Result<usize> {
    debug_assert!(len > 0 && len <= 256);
    let reject = 256 - (256 % len);
    loop {
        let bytes = random_bytes(1)?;
        if usize::from(bytes[0]) < reject {
            return Ok(usize::from(bytes[0]) % len);
        }
    }
}
