//! Canonical entry field keys (KeePass standard string fields).
//!
//! These are format-level constants: both the CLI and the app bridge build
//! and match entry fields through them instead of raw string literals.

/// Entry title.
pub const TITLE: &str = "Title";
/// Login name / account.
pub const USER_NAME: &str = "UserName";
/// Password (protected field).
pub const PASSWORD: &str = "Password";
/// Website or app URL.
pub const URL: &str = "URL";
/// Free-form notes.
pub const NOTES: &str = "Notes";
/// OTP configuration, typically an `otpauth://` URI (protected field).
pub const OTP: &str = "otp";
