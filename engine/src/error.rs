//! Error types for the engine.

use std::fmt;

/// Errors produced by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Encoding/decoding failure (base32/hex/percent).
    Encoding(String),
    /// Vault authentication failed: the supplied password/key does not match
    /// the credential data (header HMAC, block HMAC, or padding check).
    WrongPassword,
    /// The vault file is structurally invalid (bad magic, truncation,
    /// unsupported structure, XML/gzip failure, checksum mismatch).
    Format(String),
    /// A caller-supplied parameter is invalid (e.g. empty password policy).
    InvalidParameter(String),
    /// Secret is empty or otherwise unusable.
    InvalidSecret,
    /// Secret length not accepted (Yandex expects 16 or 26 bytes).
    InvalidSecretLength(usize),
    /// Yandex 26-byte secret failed its checksum.
    InvalidYandexChecksum,
    /// Algorithm not supported for the requested OTP kind.
    UnsupportedAlgorithm(String),
    /// OTP kind not supported.
    UnsupportedType(String),
    /// Digits out of the supported range (1..=10).
    InvalidDigits(u32),
    /// Period is zero.
    InvalidPeriod(u64),
    /// Counter is negative (u64 wrapper keeps this mostly impossible) or missing.
    InvalidCounter(u64),
    /// Malformed otpauth/motp URI.
    InvalidUri(String),
    /// Key-derivation error (Argon2/AES-KDF).
    Kdf(String),
    /// System clock error.
    Clock,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding(msg) => write!(f, "encoding error: {msg}"),
            Error::WrongPassword => write!(f, "wrong password (or key) for this vault"),
            Error::Format(msg) => write!(f, "invalid vault format: {msg}"),
            Error::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
            Error::InvalidSecret => write!(f, "secret is empty or invalid"),
            Error::InvalidSecretLength(len) => {
                write!(f, "invalid secret length: {len} bytes")
            }
            Error::InvalidYandexChecksum => write!(f, "yandex secret checksum invalid"),
            Error::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {a}"),
            Error::UnsupportedType(t) => write!(f, "unsupported otp type: {t}"),
            Error::InvalidDigits(d) => write!(f, "unsupported digit count: {d}"),
            Error::InvalidPeriod(p) => write!(f, "unsupported period: {p}"),
            Error::InvalidCounter(c) => write!(f, "unsupported counter: {c}"),
            Error::InvalidUri(msg) => write!(f, "invalid otp uri: {msg}"),
            Error::Kdf(msg) => write!(f, "key derivation error: {msg}"),
            Error::Clock => write!(f, "system clock unavailable"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
