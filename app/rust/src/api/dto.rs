//! Data transfer objects sent to Dart.
//!
//! Plaintext passwords are only carried by explicit reveal calls, never by
//! list/detail payloads.

/// Compact entry row for list views.
#[derive(Debug)]
pub struct EntryDto {
    /// 16-byte entry uuid, hex encoded.
    pub uuid: String,
    pub icon_id: u32,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    pub has_otp: bool,
    /// .NET epoch seconds (0 = unknown).
    pub creation: i64,
    /// .NET epoch seconds (0 = unknown).
    pub last_modification: i64,
}

/// A single entry field as stored.
#[derive(Debug)]
pub struct FieldDto {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

/// Full entry for the detail view. Protected field values are blanked;
/// use `reveal_field` to fetch them on demand.
#[derive(Debug)]
pub struct EntryDetail {
    pub uuid: String,
    pub icon_id: u32,
    pub creation: i64,
    pub last_modification: i64,
    pub fields: Vec<FieldDto>,
}

/// Parsed OTP configuration of an entry.
#[derive(Debug)]
pub struct OtpInfoDto {
    /// totp | hotp | steam | motp | yandex
    pub kind: String,
    pub issuer: String,
    pub account: String,
    /// SHA1 | SHA256 | SHA512 | MD5
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub counter: u64,
    pub has_pin: bool,
}

/// Fields of a standard password entry.
#[derive(Debug)]
pub struct PasswordEntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

/// Fields of a 2FA entry.
#[derive(Debug)]
pub struct OtpEntryInput {
    pub issuer: String,
    pub account: String,
    /// Base32 secret, or a full `otpauth://` URI (auto-detected).
    pub secret_or_uri: String,
    /// totp | hotp | steam | motp | yandex (ignored for URI input)
    pub kind: String,
    /// SHA1 | SHA256 | SHA512 (ignored for URI input)
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub counter: u64,
    /// PIN for motp/yandex (empty = none)
    pub pin: String,
}

/// Password generator policy.
#[derive(Debug)]
pub struct PasswordPolicyDto {
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub require_each_set: bool,
}
