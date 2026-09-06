//! OnePass core engine.
//!
//! Independent implementation (written from scratch) of the crypto/format
//! logic needed by OnePass. Functionally referenced from KeePassDX and Aegis,
//! but no GPL code is copied: only public standards (RFC 4226/6238, Google
//! Key URI format) and publicly documented de-facto algorithms (Steam, MOTP,
//! Yandex.Key) are re-implemented here.

pub mod cipher;
pub mod encoding;
pub mod error;
pub mod kdf;
pub mod otp;
pub mod uri;

pub use error::{Error, Result};
