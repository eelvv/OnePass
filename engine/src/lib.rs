//! OnePass core engine.
//!
//! A from-scratch implementation of the cryptographic and format logic needed
//! by OnePass: KeePass KDBX 4 read/write, OTP algorithms (RFC 4226/6238 plus
//! Steam/MOTP/Yandex), `otpauth://` URI parsing, and 2FA import/export.
//!
//! Only public standards and publicly documented de-facto algorithms are
//! implemented; no GPL code is copied.

pub mod cipher;
pub mod db;
pub mod encoding;
pub mod error;
pub mod kdf;
pub mod otp;
pub mod uri;

pub use error::{Error, Result};
