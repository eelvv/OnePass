//! OTP (2FA) integration with vault entries.
//!
//! KeePass stores a one-time-password secret as an entry's `otp` field, whose
//! value is an `otpauth://` URI (the same scheme used by KeePassXC, Aegis,
//! Google Authenticator). This module bridges [`crate::otp`] with [`Entry`].

use crate::db::{Entry, Field};
use crate::error::Result;
use crate::otp::OtpParams;
use crate::uri;

/// Parses OTP parameters from an entry's `otp` field (an `otpauth://` URI).
pub fn entry_otp(entry: &Entry) -> Option<OtpParams> {
    let uri_str = entry.get("otp")?;
    uri::parse(uri_str).ok()
}

/// Generates the current OTP code for an entry (or `None` if it has no OTP).
pub fn entry_otp_code(entry: &Entry, time_secs: u64) -> Option<String> {
    entry_otp(entry).and_then(|p| p.generate(time_secs).ok())
}

/// Sets or replaces the entry's `otp` field from OTP parameters.
pub fn set_entry_otp(entry: &mut Entry, params: &OtpParams) -> Result<()> {
    let uri_str = uri::build(params)?;
    entry.fields.retain(|f| f.key != "otp");
    entry.fields.push(Field {
        key: "otp".to_string(),
        value: uri_str,
        protected: false,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Entry;
    use crate::otp::{HashAlgorithm, OtpKind, OtpParams};

    fn totp_entry() -> Entry {
        let mut e = Entry::default();
        set_entry_otp(
            &mut e,
            &OtpParams {
                kind: OtpKind::Totp,
                secret: b"12345678901234567890".to_vec(),
                digits: 8,
                period: 30,
                algorithm: HashAlgorithm::Sha1,
                issuer: "Example".to_string(),
                account: "alice".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        e
    }

    #[test]
    fn roundtrip_through_otp_field() {
        let e = totp_entry();
        let params = entry_otp(&e).expect("otp parsed");
        assert_eq!(params.kind, OtpKind::Totp);
        assert_eq!(params.secret, b"12345678901234567890");
        // RFC 6238 vector: secret "12345678901234567890", T=59 → "94287082".
        assert_eq!(entry_otp_code(&e, 59).unwrap(), "94287082");
    }

    #[test]
    fn no_otp_returns_none() {
        let e = Entry::default();
        assert!(entry_otp(&e).is_none());
        assert!(entry_otp_code(&e, 59).is_none());
    }
}
