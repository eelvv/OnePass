//! Creates a demo password vault with several example website entries and
//! saves it as a KDBX 4 file.
//!
//! Usage: cargo run --release --example create_demo -- [output] [password]

use onepass_engine::db::{random_bytes, save, set_entry_otp, Entry, Field, Group, Vault};
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams};

fn field(key: &str, value: &str, protected: bool) -> Field {
    Field {
        key: key.to_string(),
        value: value.to_string(),
        protected,
    }
}

fn entry(title: &str, username: &str, password: &str, url: &str, notes: &str) -> Entry {
    let mut e = Entry {
        uuid: random_bytes(16).expect("uuid"),
        ..Default::default()
    };
    e.fields.push(field("Title", title, false));
    e.fields.push(field("UserName", username, false));
    e.fields.push(field("Password", password, true));
    e.fields.push(field("URL", url, false));
    if !notes.is_empty() {
        e.fields.push(field("Notes", notes, false));
    }
    e
}

fn otp_entry(title: &str, username: &str, secret_b32: &str, kind: OtpKind, counter: u64) -> Entry {
    let mut e = entry(
        title,
        username,
        "unused-password",
        "",
        "2FA entry (TOTP/HOTP)",
    );
    e.fields.retain(|f| f.key != "Password" && f.key != "URL");
    set_entry_otp(
        &mut e,
        &OtpParams {
            kind,
            secret: onepass_engine::encoding::base32::decode_tolerant(secret_b32)
                .expect("base32 secret"),
            digits: if matches!(kind, OtpKind::Steam) { 5 } else { 6 },
            period: 30,
            algorithm: HashAlgorithm::Sha1,
            issuer: title.to_string(),
            account: username.to_string(),
            counter,
            pin: None,
        },
    )
    .expect("set otp");
    e
}

fn group(name: &str) -> Group {
    Group {
        uuid: random_bytes(16).expect("group uuid"),
        name: name.to_string(),
        ..Default::default()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("../examples/output.kdbx");
    let password = args.get(2).map(|s| s.as_str()).unwrap_or("example1");

    let mut dev = group("Development");
    dev.entries.push(entry(
        "GitHub",
        "octocat@example.com",
        "gh!2026-Octocat",
        "https://github.com",
        "Main account",
    ));
    dev.entries.push(entry(
        "GitLab",
        "dev@example.com",
        "gl#2026-Dev",
        "https://gitlab.com",
        "",
    ));
    dev.entries.push(entry(
        "Stack Overflow",
        "coder@example.com",
        "so?2026-Coder",
        "https://stackoverflow.com",
        "",
    ));

    let mut social = group("Social");
    social.entries.push(entry(
        "Google",
        "user@gmail.com",
        "go0gle-2026!",
        "https://accounts.google.com",
        "2FA enabled",
    ));
    social.entries.push(entry(
        "Twitter",
        "@example_user",
        "tw!tter-2026",
        "https://twitter.com",
        "",
    ));
    social.entries.push(entry(
        "Instagram",
        "example.ig",
        "insta-2026#",
        "https://instagram.com",
        "",
    ));

    let mut email = group("Email");
    email.entries.push(entry(
        "Outlook",
        "user@outlook.com",
        "outlook-2026!",
        "https://outlook.com",
        "Backup email",
    ));

    let mut shopping = group("Shopping");
    shopping.entries.push(entry(
        "Amazon",
        "shopper@example.com",
        "amzn-2026!",
        "https://amazon.com",
        "",
    ));
    shopping.entries.push(entry(
        "eBay",
        "bidder@example.com",
        "ebay-2026#",
        "https://ebay.com",
        "",
    ));

    let mut twofa = group("2FA");
    twofa.entries.push(otp_entry(
        "GitHub 2FA",
        "octocat@example.com",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // "12345678901234567890"
        OtpKind::Totp,
        0,
    ));
    twofa.entries.push(otp_entry(
        "GitLab 2FA",
        "dev@example.com",
        "JBSWY3DPEHPK3PXP", // "Hello!\xDE\xAD\xBE\xEF"
        OtpKind::Hotp,
        1,
    ));

    let mut vault = Vault {
        database_name: "My Passwords".to_string(),
        root: Group {
            uuid: random_bytes(16).expect("root uuid"),
            name: "Root".to_string(),
            ..Default::default()
        },
    };
    vault.root.groups.push(dev);
    vault.root.groups.push(social);
    vault.root.groups.push(email);
    vault.root.groups.push(shopping);
    vault.root.groups.push(twofa);

    let saved = save(&vault, password.as_bytes()).expect("save");
    std::fs::write(output, &saved).expect("write output");
    println!(
        "Saved {} bytes to {output} (password: {password}, 5 groups, 11 entries incl. 2 OTP)",
        saved.len()
    );
}
