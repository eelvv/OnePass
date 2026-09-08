//! App-core focused engine checks: error classification, entry times,
//! KDF save options, and password-policy generation.

use onepass_engine::db::{
    generate_password_with_policy, open, random_bytes, save, save_with, Entry, PasswordPolicy,
    SaveOptions, Times, Vault, PASSWORD, TITLE, USER_NAME,
};
use onepass_engine::error::Error;

fn demo_vault() -> Vault {
    let mut vault = Vault::create("test").expect("create");
    let mut entry = Entry {
        uuid: random_bytes(16).expect("uuid"),
        ..Default::default()
    };
    entry.set_field(TITLE, "Example", false);
    entry.set_field(USER_NAME, "user", false);
    entry.set_field(PASSWORD, "hunter2", true);
    vault.root.entries.push(entry);
    vault
}

#[test]
fn wrong_password_is_classified() {
    let saved = save(&demo_vault(), b"correct horse").expect("save");
    assert!(matches!(open(&saved, b"wrong"), Err(Error::WrongPassword)));
}

#[test]
fn corrupted_header_is_classified_as_format() {
    let mut saved = save(&demo_vault(), b"pw").expect("save");
    // Flip a byte inside the plaintext header (before any HMAC coverage).
    assert!(saved.len() > 32);
    saved[10] ^= 0xFF;
    match open(&saved, b"pw") {
        Err(Error::Format(_)) => {}
        Err(e) => panic!("expected Format, got {e:?}"),
        Ok(_) => panic!("corrupted header opened"),
    }
}

#[test]
fn corrupted_payload_is_rejected() {
    let mut saved = save(&demo_vault(), b"pw").expect("save");
    // Flip a byte inside the terminating HMAC block of the payload stream.
    let n = saved.len();
    saved[n - 10] ^= 0xFF;
    assert!(matches!(open(&saved, b"pw"), Err(Error::WrongPassword)));
}

#[test]
fn times_survive_roundtrip() {
    let mut vault = demo_vault();
    vault.root.entries[0].times = Times {
        creation: 700_000_000,
        last_modification: 800_000_000,
    };

    let saved = save(&vault, b"pw").expect("save");
    let reopened = open(&saved, b"pw").expect("open");
    assert_eq!(
        reopened.root.entries[0].times,
        Times {
            creation: 700_000_000,
            last_modification: 800_000_000
        }
    );
}

#[test]
fn zero_times_are_rewritten_on_save() {
    let vault = demo_vault(); // times left at zero
    let saved = save(&vault, b"pw").expect("save");
    let reopened = open(&saved, b"pw").expect("open");
    assert!(reopened.root.entries[0].times.creation != 0);
}

#[test]
fn save_with_mobile_options_roundtrip() {
    let vault = demo_vault();
    let saved = save_with(&vault, b"pw", &SaveOptions::mobile()).expect("save");
    let reopened = open(&saved, b"pw").expect("open");
    assert_eq!(reopened.root.entries[0].title(), Some("Example"));
}

#[test]
fn password_policy_is_respected() {
    let policy = PasswordPolicy {
        upper: true,
        lower: true,
        digits: true,
        symbols: false,
        exclude_ambiguous: true,
        require_each_set: true,
    };
    for _ in 0..64 {
        let pw = generate_password_with_policy(20, &policy).expect("generate");
        assert_eq!(pw.chars().count(), 20);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(!pw.chars().any(|c| SYMBOLS.contains(&(c as u8))));
        assert!(!pw.chars().any(|c| AMBIGUOUS.contains(&(c as u8))));
    }

    // Length below the required-set count must fail.
    assert!(generate_password_with_policy(2, &policy).is_err());

    // No sets enabled must fail.
    assert!(generate_password_with_policy(
        8,
        &PasswordPolicy {
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
            require_each_set: false,
        }
    )
    .is_err());
}

const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";
const AMBIGUOUS: &[u8] = b"IOl01|'`\".,;:";
