//! Tests for 2FA import/export (transfer module) and the Google Authenticator
//! migration codec.

use onepass_engine::db::{
    entry_from_otpauth_uri, entry_otp, entry_otp_code, export_aegis_json, export_otpauth_uris,
    import_aegis_json, import_google_migration, import_otpauth_uris, open, otp_entries,
    random_bytes, save, Entry, Group, Vault,
};
use onepass_engine::encoding::base32;
use onepass_engine::otp::migration::MigrationEntry;
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams};

const SECRET: &[u8] = b"12345678901234567890";

fn totp_params() -> OtpParams {
    OtpParams {
        kind: OtpKind::Totp,
        secret: SECRET.to_vec(),
        digits: 8,
        period: 30,
        algorithm: HashAlgorithm::Sha1,
        issuer: "GitHub".to_string(),
        account: "alice".to_string(),
        ..Default::default()
    }
}

fn migration_entry(p: &OtpParams) -> MigrationEntry {
    MigrationEntry {
        secret: p.secret.clone(),
        name: p.account.clone(),
        issuer: p.issuer.clone(),
        algorithm: p.algorithm,
        digits: p.digits,
        kind: p.kind,
        counter: p.counter,
    }
}

// --- Google Authenticator migration: payload cross-checked against an
// --- independent Python protobuf encoder (varint/struct implementation).

#[test]
fn migration_known_vector() {
    // Python reference encodes one OtpParameters entry:
    //   secret=b"12345678901234567890", name="alice", issuer="GitHub",
    //   algorithm=SHA1(1), digits=SIX(1), type=TOTP(2), counter=0
    // wrapped in a MigrationPayload with version=1, batch_size=1.
    let payload_hex = "0a2d0a1431323334353637383930313233343536373839301205616c6963651a0647697448756220012801300238001001180120002800";
    let bytes: Vec<u8> = (0..payload_hex.len() / 2)
        .map(|i| u8::from_str_radix(&payload_hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();

    let parsed = onepass_engine::otp::migration::parse_payload(&bytes).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].secret, SECRET);
    assert_eq!(parsed[0].name, "alice");
    assert_eq!(parsed[0].issuer, "GitHub");
    assert_eq!(parsed[0].algorithm, HashAlgorithm::Sha1);
    assert_eq!(parsed[0].digits, 6);
    assert_eq!(parsed[0].kind, OtpKind::Totp);
}

#[test]
fn migration_uri_roundtrip() {
    let entries = vec![migration_entry(&totp_params())];
    let uri = onepass_engine::otp::migration::build_migration_uri(&entries).unwrap();
    assert!(uri.starts_with("otpauth-migration://offline?data="));
    let parsed = onepass_engine::otp::migration::parse_migration_uri(&uri).unwrap();
    assert_eq!(parsed, entries);
}

// --- adding entries from otpauth URIs

#[test]
fn add_from_otpauth_uri() {
    let b32 = base32::encode(SECRET);
    let uri = format!("otpauth://totp/GitHub:alice?secret={b32}&digits=8&period=30&issuer=GitHub");
    let entry = entry_from_otpauth_uri(&uri).unwrap();
    assert_eq!(entry.title(), Some("GitHub"));
    assert_eq!(entry.username(), Some("alice"));
    assert_eq!(entry_otp_code(&entry, 59).unwrap(), "94287082");
}

// --- otpauth URI list import/export

#[test]
fn uri_list_roundtrip() {
    let b32 = base32::encode(SECRET);
    let text = format!(
        "# comment line\n\
         otpauth://totp/GitHub:alice?secret={b32}&digits=8&issuer=GitHub\n\
         \n\
         otpauth://totp/GitLab:bob?secret={b32}&issuer=GitLab\n"
    );
    let entries = import_otpauth_uris(&text).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].title(), Some("GitHub"));
    assert_eq!(entry_otp_code(&entries[0], 59).unwrap(), "94287082");

    let refs: Vec<&Entry> = entries.iter().collect();
    let exported = export_otpauth_uris(&refs).unwrap();
    assert_eq!(exported.lines().count(), 2);
    let re = import_otpauth_uris(&exported).unwrap();
    assert_eq!(entry_otp_code(&re[0], 59).unwrap(), "94287082");
}

// --- Aegis JSON import/export

#[test]
fn aegis_json_roundtrip() {
    let b32 = base32::encode(SECRET);
    let aegis = format!(
        r#"{{
        "version": 1,
        "header": {{"slots": null, "params": null}},
        "db": {{
            "version": 3,
            "entries": [
                {{
                    "type": "totp",
                    "uuid": "01234567-89ab-cdef-0123-456789abcdef",
                    "name": "alice",
                    "issuer": "GitHub",
                    "note": "main account",
                    "favorite": false,
                    "icon": null, "icon_mime": null, "icon_hash": null,
                    "info": {{
                        "secret": "{b32}",
                        "algo": "SHA1",
                        "digits": 6,
                        "period": 30
                    }},
                    "groups": []
                }}
            ],
            "groups": []
        }}
    }}"#
    );

    let entries = import_aegis_json(aegis.as_bytes()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title(), Some("GitHub"));
    assert_eq!(entries[0].username(), Some("alice"));
    assert_eq!(entries[0].get("Notes"), Some("main account"));

    let refs: Vec<&Entry> = entries.iter().collect();
    let exported = export_aegis_json(&refs).unwrap();
    let re = import_aegis_json(&exported).unwrap();
    assert_eq!(re.len(), 1);
    assert_eq!(
        entry_otp(&re[0]).unwrap().secret,
        entry_otp(&entries[0]).unwrap().secret
    );
}

// --- Google Authenticator migration import into entries

#[test]
fn google_migration_import() {
    let uri =
        onepass_engine::otp::migration::build_migration_uri(&[migration_entry(&totp_params())])
            .unwrap();
    let imported = import_google_migration(&uri).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].title(), Some("GitHub"));
    assert_eq!(entry_otp_code(&imported[0], 59).unwrap(), "94287082");
}

// --- end-to-end: imported OTP entries survive save → open

#[test]
fn imported_entries_survive_save_open() {
    let b32 = base32::encode(SECRET);
    let uri = format!("otpauth://totp/GitHub:alice?secret={b32}&digits=8&issuer=GitHub");
    let entry = entry_from_otpauth_uri(&uri).unwrap();

    let vault = Vault {
        database_name: "otp".to_string(),
        root: Group {
            uuid: random_bytes(16).unwrap(),
            name: "Root".to_string(),
            entries: vec![entry],
            ..Default::default()
        },
        ..Default::default()
    };

    let saved = save(&vault, b"pw").unwrap();
    let opened = open(&saved, b"pw").unwrap();
    let otps = otp_entries(&opened);
    assert_eq!(otps.len(), 1);
    assert_eq!(entry_otp_code(otps[0], 59).unwrap(), "94287082");
}
