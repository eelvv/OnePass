//! Imports OTP entries into a new (or existing) KDBX file.
//!
//! Usage:
//!   cargo run --release --example import_otp -- <source> <password> <output.kdbx> <output-password>
//!
//! The source is detected by content:
//!   - Aegis plaintext JSON vault
//!   - otpauth:// URI list (one per line)
//!   - Google Authenticator migration URI (otpauth-migration://…)

use onepass_engine::db::{
    import_aegis_json, import_google_migration, import_otpauth_uris, open, random_bytes, save,
    Entry, Group, Vault,
};

fn detect_and_import(data: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(data).trim().to_string();

    if text.starts_with('{') {
        println!("Detected: Aegis JSON");
        return import_aegis_json(data).expect("import aegis json");
    }
    if text.starts_with("otpauth-migration://") {
        println!("Detected: Google Authenticator migration");
        return import_google_migration(&text).expect("import migration");
    }
    if text.starts_with("otpauth://") {
        println!("Detected: otpauth URI list");
        return import_otpauth_uris(&text).expect("import uri list");
    }
    panic!("Unrecognized source format");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("../examples/otpauth-uris.txt");
    let output = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("../examples/imported.kdbx");
    let out_password = args.get(3).map(|s| s.as_str()).unwrap_or("example1");

    let data = std::fs::read(input).expect("read input");
    let entries = detect_and_import(&data);
    println!("Imported {} entries", entries.len());

    // If the output already exists, merge into it; otherwise create fresh.
    let mut vault = match std::fs::read(output) {
        Ok(existing) => {
            let mut v = open(&existing, out_password.as_bytes()).expect("open existing output");
            v.root.entries.extend(entries);
            v
        }
        Err(_) => Vault {
            database_name: "Imported 2FA".to_string(),
            root: Group {
                uuid: random_bytes(16).unwrap(),
                name: "Root".to_string(),
                entries,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    if vault.database_name.is_empty() {
        vault.database_name = "Imported 2FA".to_string();
    }

    let saved = save(&vault, out_password.as_bytes()).expect("save");
    std::fs::write(output, &saved).expect("write output");
    println!(
        "Saved {} bytes to {output} (password: {out_password})",
        saved.len()
    );
}
