//! OTP parameter model and validation.

use super::yandex;
use crate::error::{Error, Result};

/// Hash algorithms supported by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Md5,
}

impl HashAlgorithm {
    /// Parses an algorithm name, tolerating prefixes like `Hmac-` / `HMAC-`.
    pub fn parse(s: &str) -> Result<Self> {
        let norm: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        let norm = norm.replace("HMAC", "");
        match norm.as_str() {
            "" | "SHA1" | "SHA" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            "MD5" => Ok(Self::Md5),
            other => Err(Error::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Canonical name as used in URIs/vaults.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Md5 => "MD5",
        }
    }

    /// Whether the algorithm can be used with HMAC (i.e. HOTP/TOTP/Steam).
    /// MD5 is only used by MOTP.
    pub fn is_hmac(&self) -> bool {
        !matches!(self, Self::Md5)
    }
}

/// Kinds of one-time password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtpKind {
    /// RFC 4226 event-based.
    Hotp,
    /// RFC 6238 time-based.
    Totp,
    /// Steam (TOTP variant with its own alphabet).
    Steam,
    /// mobile-OTP (MD5, PIN, 10s windows).
    Motp,
    /// Yandex.Key (SHA-256, PIN, base-26 alphabet).
    Yandex,
}

impl OtpKind {
    /// Parses a URI authority / type id.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hotp" => Ok(Self::Hotp),
            "totp" => Ok(Self::Totp),
            "steam" => Ok(Self::Steam),
            "motp" => Ok(Self::Motp),
            "yandex" | "yaotp" => Ok(Self::Yandex),
            other => Err(Error::UnsupportedType(other.to_string())),
        }
    }

    /// URI authority / type id.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hotp => "hotp",
            Self::Totp => "totp",
            Self::Steam => "steam",
            Self::Motp => "motp",
            Self::Yandex => "yaotp",
        }
    }
}

/// Defaults shared with Aegis / the Google Key URI format.
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha1;
pub const DEFAULT_PERIOD: u64 = 30;

/// A validated OTP entry: the union of all supported kinds.
///
/// Field usage by kind:
/// - Hotp: secret, algorithm (HMAC), digits, counter
/// - Totp: secret, algorithm, digits, period
/// - Steam: secret, period (digits/algorithm fixed to 5/SHA1)
/// - Motp: secret, pin, period (fixed 10, digits 6, MD5)
/// - Yandex: secret (16 bytes), pin, period (fixed 30, digits 8, SHA256)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParams {
    pub kind: OtpKind,
    pub secret: Vec<u8>,
    pub algorithm: HashAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub counter: u64,
    pub pin: Option<String>,
    /// Display label parts (also used when building URIs).
    pub issuer: String,
    pub account: String,
}

impl Default for OtpParams {
    fn default() -> Self {
        Self {
            kind: OtpKind::Totp,
            secret: Vec::new(),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            counter: 0,
            pin: None,
            issuer: String::new(),
            account: String::new(),
        }
    }
}

impl OtpParams {
    /// Applies kind-specific fixed values and validates the entry.
    pub fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(Error::InvalidSecret);
        }
        if self.digits == 0 || self.digits > 10 {
            return Err(Error::InvalidDigits(self.digits));
        }
        match self.kind {
            OtpKind::Hotp => {
                if !self.algorithm.is_hmac() {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "HOTP with {}",
                        self.algorithm.as_str()
                    )));
                }
            }
            OtpKind::Totp | OtpKind::Steam => {
                if self.period == 0 {
                    return Err(Error::InvalidPeriod(self.period));
                }
                if !self.algorithm.is_hmac() {
                    return Err(Error::UnsupportedAlgorithm(format!(
                        "TOTP with {}",
                        self.algorithm.as_str()
                    )));
                }
            }
            OtpKind::Motp => {
                if self.period == 0 {
                    return Err(Error::InvalidPeriod(self.period));
                }
                // PIN is not part of the URI; it is supplied at generation
                // time, so it is not required here.
            }
            OtpKind::Yandex => {
                if self.period == 0 {
                    return Err(Error::InvalidPeriod(self.period));
                }
                let _ = yandex::normalize_secret(&self.secret)?;
            }
        }
        Ok(())
    }

    /// Generates a code at the given UNIX time.
    pub fn generate(&self, time_secs: u64) -> Result<String> {
        super::generate(self, time_secs)
    }

    /// Generates a code at the current time.
    pub fn generate_now(&self) -> Result<String> {
        super::generate_now(self)
    }

    /// Seconds until the current window rotates (time-based kinds only).
    pub fn seconds_remaining(&self, time_secs: u64) -> Result<u64> {
        super::seconds_remaining(self, time_secs)
    }
}
