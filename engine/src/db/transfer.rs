//! Adding, importing and exporting 2FA (OTP) entries.
//!
//! Supported formats:
//! - `otpauth://` URI lists (one URI per line) — the universal interchange
//!   format also produced by Google Authenticator, FreeOTP, andOTP, etc.
//! - Aegis plaintext JSON vaults (`{"version":1,"header":…,"db":{…}}`).
//! - Google Authenticator migration URIs (`otpauth-migration://offline?data=…`).

use crate::db::otp::entry_otp;
use crate::db::{random_bytes, Entry, Field, Group};
use crate::encoding::base32;
use crate::error::{Error, Result};
use crate::otp::migration::{
    build_migration_uri, parse_migration_uri, MigrationEntry,
};
use crate::otp::{HashAlgorithm, OtpKind, OtpParams};
use crate::uri;

// ---------------------------------------------------------------------------
// adding 2FA entries

/// Creates a new entry from an `otpauth://` URI (what a 2FA QR code encodes).
///
/// The entry gets `Title` (issuer), `UserName` (account) and a protected `otp`
/// field holding the URI.
pub fn entry_from_otpauth_uri(uri_str: &str) -> Result<Entry> {
    let params = uri::parse(uri_str)?;
    entry_from_otp_params(&params)
}

/// Creates a new entry from explicit OTP parameters.
pub fn entry_from_otp_params(params: &OtpParams) -> Result<Entry> {
    let otp_uri = uri::build(params)?;
    let title = if params.issuer.is_empty() {
        params.account.clone()
    } else {
        params.issuer.clone()
    };

    let mut entry = Entry {
        uuid: random_bytes(16)?,
        ..Default::default()
    };
    entry
        .fields
        .push(Field { key: "Title".to_string(), value: title, protected: false });
    if !params.account.is_empty() {
        entry.fields.push(Field {
            key: "UserName".to_string(),
            value: params.account.clone(),
            protected: false,
        });
    }
    entry.fields.push(Field {
        key: "otp".to_string(),
        value: otp_uri,
        protected: true,
    });
    Ok(entry)
}

/// Collects every entry that carries an `otp` field, flattening groups.
pub fn otp_entries(vault: &crate::db::Vault) -> Vec<&Entry> {
    fn walk<'a>(g: &'a Group, out: &mut Vec<&'a Entry>) {
        for e in &g.entries {
            if e.get("otp").is_some() {
                out.push(e);
            }
        }
        for sg in &g.groups {
            walk(sg, out);
        }
    }
    let mut out = Vec::new();
    walk(&vault.root, &mut out);
    out
}

// ---------------------------------------------------------------------------
// import

/// Imports entries from a newline-separated list of `otpauth://` URIs.
pub fn import_otpauth_uris(text: &str) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(entry_from_otpauth_uri(line)?);
    }
    Ok(out)
}

/// Imports entries from an Aegis plaintext JSON vault.
pub fn import_aegis_json(json: &[u8]) -> Result<Vec<Entry>> {
    let root: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| Error::Encoding(format!("aegis json: {e}")))?;
    let db = root
        .get("db")
        .ok_or_else(|| Error::Encoding("aegis json: missing db".to_string()))?;
    let entries = db
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Encoding("aegis json: missing entries".to_string()))?;

    let mut out = Vec::new();
    for e in entries {
        match aegis_entry_to_entry(e) {
            Ok(entry) => out.push(entry),
            Err(Error::UnsupportedAlgorithm(_) | Error::UnsupportedType(_)) => {
                continue; // skip exotic/unreadable entries
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Imports entries from a Google Authenticator migration URI.
pub fn import_google_migration(uri_str: &str) -> Result<Vec<Entry>> {
    let migrated = parse_migration_uri(uri_str)?;
    let mut out = Vec::new();
    for m in migrated {
        let params = OtpParams {
            kind: m.kind,
            secret: m.secret,
            algorithm: m.algorithm,
            digits: m.digits,
            period: 30,
            counter: m.counter,
            pin: None,
            issuer: m.issuer.clone(),
            account: m.name.clone(),
        };
        match entry_from_otp_params(&params) {
            Ok(entry) => out.push(entry),
            Err(Error::UnsupportedAlgorithm(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn aegis_entry_to_entry(value: &serde_json::Value) -> Result<Entry> {
    let kind_str = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("totp");
    let info = value
        .get("info")
        .ok_or_else(|| Error::Encoding("aegis entry: missing info".to_string()))?;

    let kind = match kind_str {
        "totp" => OtpKind::Totp,
        "hotp" => OtpKind::Hotp,
        "steam" => OtpKind::Steam,
        "motp" => OtpKind::Motp,
        "yandex" => OtpKind::Yandex,
        other => return Err(Error::UnsupportedType(other.to_string())),
    };

    let secret_b32 = info
        .get("secret")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let mut algo_str = info
        .get("algo")
        .and_then(|v| v.as_str())
        .unwrap_or("SHA1")
        .to_string();
    let digits = info.get("digits").and_then(|v| v.as_u64()).unwrap_or(6) as u32;

    // Aegis workaround: non-mOTP entries must not be MD5.
    if algo_str.eq_ignore_ascii_case("MD5") && kind != OtpKind::Motp {
        algo_str = "SHA1".to_string();
    }
    let algorithm = HashAlgorithm::parse(&algo_str)?;

    let secret = base32::decode_tolerant(secret_b32)?;
    if secret.is_empty() {
        return Err(Error::InvalidSecret);
    }

    let period = info.get("period").and_then(|v| v.as_u64()).unwrap_or(match kind {
        OtpKind::Motp => 10,
        _ => 30,
    });
    let counter = info.get("counter").and_then(|v| v.as_u64()).unwrap_or(0);
    let pin = info
        .get("pin")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let issuer = value
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let note = value
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let params = OtpParams {
        kind,
        secret,
        algorithm,
        digits,
        period,
        counter,
        pin,
        issuer: issuer.clone(),
        account: name.clone(),
    };

    let otp_uri = uri::build(&params)?;
    let mut entry = Entry {
        uuid: random_bytes(16)?,
        ..Default::default()
    };
    entry.fields.push(Field {
        key: "Title".to_string(),
        value: if issuer.is_empty() { name.clone() } else { issuer },
        protected: false,
    });
    entry.fields.push(Field {
        key: "UserName".to_string(),
        value: name,
        protected: false,
    });
    if !note.is_empty() {
        entry.fields.push(Field {
            key: "Notes".to_string(),
            value: note,
            protected: false,
        });
    }
    entry.fields.push(Field {
        key: "otp".to_string(),
        value: otp_uri,
        protected: true,
    });
    Ok(entry)
}

// ---------------------------------------------------------------------------
// export

/// Exports OTP entries as a newline-separated list of `otpauth://` URIs.
pub fn export_otpauth_uris(entries: &[&Entry]) -> Result<String> {
    let mut out = String::new();
    for e in entries {
        let params = entry_otp(e).ok_or_else(|| {
            Error::Encoding("entry has no readable otp field".to_string())
        })?;
        out.push_str(&uri::build(&params)?);
        out.push('\n');
    }
    Ok(out)
}

/// Exports OTP entries as an Aegis plaintext JSON vault (importable by Aegis).
pub fn export_aegis_json(entries: &[&Entry]) -> Result<Vec<u8>> {
    use serde_json::json;

    let mut arr = Vec::new();
    for e in entries {
        let params = entry_otp(e).ok_or_else(|| {
            Error::Encoding("entry has no readable otp field".to_string())
        })?;

        let mut info = serde_json::Map::new();
        info.insert(
            "secret".to_string(),
            json!(base32::encode(&params.secret)),
        );
        info.insert(
            "algo".to_string(),
            json!(params.algorithm.as_str()),
        );
        info.insert("digits".to_string(), json!(params.digits));
        match params.kind {
            OtpKind::Hotp => {
                info.insert("counter".to_string(), json!(params.counter));
            }
            _ => {
                info.insert("period".to_string(), json!(params.period));
            }
        }
        if let Some(pin) = &params.pin {
            info.insert("pin".to_string(), json!(pin));
        }

        arr.push(json!({
            "type": aegis_type(params.kind),
            "uuid": uuid_string(e),
            "name": e.username().unwrap_or(""),
            "issuer": e.title().unwrap_or(""),
            "note": e.get("Notes").unwrap_or(""),
            "favorite": false,
            "icon": serde_json::Value::Null,
            "icon_mime": serde_json::Value::Null,
            "icon_hash": serde_json::Value::Null,
            "info": serde_json::Value::Object(info),
            "groups": [],
        }));
    }

    let doc = json!({
        "version": 1,
        "header": { "slots": serde_json::Value::Null, "params": serde_json::Value::Null },
        "db": {
            "version": 3,
            "entries": arr,
            "groups": [],
        },
    });
    serde_json::to_vec_pretty(&doc).map_err(|e| Error::Encoding(format!("aegis json: {e}")))
}

/// Exports OTP entries as a Google Authenticator migration URI.
pub fn export_google_migration(entries: &[&Entry]) -> Result<String> {
    let mut migrated = Vec::new();
    for e in entries {
        let params = entry_otp(e).ok_or_else(|| {
            Error::Encoding("entry has no readable otp field".to_string())
        })?;
        if !matches!(params.kind, OtpKind::Hotp | OtpKind::Totp) {
            continue; // the migration format only knows HOTP/TOTP
        }
        migrated.push(MigrationEntry {
            secret: params.secret,
            name: params.account,
            issuer: params.issuer,
            algorithm: params.algorithm,
            digits: params.digits,
            kind: params.kind,
            counter: params.counter,
        });
    }
    build_migration_uri(&migrated)
}

fn aegis_type(kind: OtpKind) -> &'static str {
    match kind {
        OtpKind::Hotp => "hotp",
        OtpKind::Totp => "totp",
        OtpKind::Steam => "steam",
        OtpKind::Motp => "motp",
        OtpKind::Yandex => "yandex",
    }
}

/// Formats the entry UUID (16 bytes, KeePass order) as a canonical UUID
/// string, as expected by Aegis.
fn uuid_string(entry: &Entry) -> String {
    let bytes = &entry.uuid;
    if bytes.len() != 16 {
        return String::new();
    }
    let msb = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let lsb = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (msb >> 32) as u32,
        ((msb >> 16) & 0xFFFF) as u16,
        (msb & 0xFFFF) as u16,
        ((lsb >> 48) & 0xFFFF) as u16,
        lsb & 0xFFFF_FFFF_FFFF
    )
}
