//! Bridge error type surfaced to Dart as a generated exception.
//!
//! Kept as a struct + fieldless enum (instead of a data-carrying enum) so
//! the generated Dart side needs no freezed/build_runner toolchain.

use onepass_engine::error::Error as EngineError;

/// Coarse error category the UI can switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The supplied password does not match the vault.
    WrongPassword,
    /// The vault file is structurally invalid.
    Format,
    /// File system failure (read/write).
    Io,
    /// Invalid user input (bad secret, bad policy, unknown uuid, ...).
    InvalidParameter,
    /// The operation requires an unlocked vault (or conflicts with one).
    SessionState,
    /// Anything else.
    Other,
}

/// Bridge error: a category plus a human-readable message.
#[derive(Debug, Clone)]
pub struct BridgeError {
    pub kind: ErrorKind,
    pub message: String,
}

impl BridgeError {
    /// Internal constructor; also used by the generated wire code to
    /// rebuild errors crossing the boundary.
    #[flutter_rust_bridge::frb(ignore)]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::WrongPassword => write!(f, "wrong password for this vault"),
            ErrorKind::Format => write!(f, "invalid vault format: {}", self.message),
            ErrorKind::Io => write!(f, "io error: {}", self.message),
            ErrorKind::InvalidParameter => write!(f, "invalid parameter: {}", self.message),
            ErrorKind::SessionState => write!(f, "session state error: {}", self.message),
            ErrorKind::Other => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<EngineError> for BridgeError {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::WrongPassword => {
                BridgeError::new(ErrorKind::WrongPassword, "wrong password for this vault")
            }
            EngineError::Format(m) => BridgeError::new(ErrorKind::Format, m),
            EngineError::InvalidParameter(m) => BridgeError::new(ErrorKind::InvalidParameter, m),
            EngineError::InvalidSecret => {
                BridgeError::new(ErrorKind::InvalidParameter, "empty or invalid secret")
            }
            EngineError::InvalidSecretLength(n) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("invalid secret length: {n} bytes"),
            ),
            EngineError::InvalidYandexChecksum => {
                BridgeError::new(ErrorKind::InvalidParameter, "yandex secret checksum failed")
            }
            EngineError::InvalidUri(m) => {
                BridgeError::new(ErrorKind::InvalidParameter, format!("invalid uri: {m}"))
            }
            EngineError::InvalidDigits(d) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("unsupported digit count: {d}"),
            ),
            EngineError::InvalidPeriod(p) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("unsupported period: {p}"),
            ),
            EngineError::InvalidCounter(c) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("unsupported counter: {c}"),
            ),
            EngineError::UnsupportedAlgorithm(a) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("unsupported algorithm: {a}"),
            ),
            EngineError::UnsupportedType(t) => BridgeError::new(
                ErrorKind::InvalidParameter,
                format!("unsupported otp type: {t}"),
            ),
            EngineError::Kdf(m) => BridgeError::new(ErrorKind::Format, format!("kdf: {m}")),
            EngineError::Encoding(m) => {
                BridgeError::new(ErrorKind::Other, format!("encoding: {m}"))
            }
            EngineError::Clock => BridgeError::new(ErrorKind::Other, "system clock unavailable"),
        }
    }
}

pub type BridgeResult<T> = Result<T, BridgeError>;
