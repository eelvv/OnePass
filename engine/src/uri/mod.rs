//! `otpauth://` (Google Key URI format) and `motp://` parsing/building.

pub mod otpauth;

pub use otpauth::{build, parse};
