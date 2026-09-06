//! End-to-end: an OTP entry survives save → open and still generates the
//! correct code (RFC 6238 vector).

use onepass_engine::db::{
    entry_otp_code, open, random_bytes, save, set_entry_otp, Entry, Field, Group, Vault,
};
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams};

#[test]
fn otp_survives_save_open() {
    let mut entry = Entry {
        uuid: random_bytes(16).unwrap(),
        ..Default::default()
    };
    entry.fields.push(Field {
        key: "Title".to_string(),
        value: "GitHub".to_string(),
        protected: false,
    });
    entry.fields.push(Field {
        key: "UserName".to_string(),
        value: "alice".to_string(),
        protected: false,
    });
    set_entry_otp(
        &mut entry,
        &OtpParams {
            kind: OtpKind::Totp,
            secret: b"12345678901234567890".to_vec(),
            digits: 8,
            period: 30,
            algorithm: HashAlgorithm::Sha1,
            issuer: "GitHub".to_string(),
            account: "alice".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let vault = Vault {
        database_name: "otp test".to_string(),
        root: Group {
            uuid: random_bytes(16).unwrap(),
            name: "Root".to_string(),
            entries: vec![entry],
            ..Default::default()
        },
    };

    let saved = save(&vault, b"test-pass").unwrap();
    let opened = open(&saved, b"test-pass").unwrap();

    let e = &opened.root.entries[0];
    assert_eq!(e.title(), Some("GitHub"));
    assert_eq!(e.username(), Some("alice"));
    // RFC 6238: secret "12345678901234567890", T=59 → "94287082".
    assert_eq!(entry_otp_code(e, 59).unwrap(), "94287082");
}
