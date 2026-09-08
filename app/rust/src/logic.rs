//! Core vault-session logic. Deliberately outside `crate::api` so the FRB
//! scanner never sees it: `api/vault.rs` holds thin Dart-facing wrappers,
//! everything real happens here. The decrypted vault and the master password
//! only ever live inside the global session on the Rust side.

use zeroize::Zeroizing;

use onepass_engine::db::{
    detect_and_import, entry_from_otp_params, entry_otp, entry_otp_code, export_aegis_json,
    export_otpauth_uris, import_otpauth_uris, otp_entries, random_bytes, save_with, set_entry_otp,
    Entry, Group, SaveOptions, Times, Vault, NOTES, PASSWORD, TITLE, URL, USER_NAME,
};
use onepass_engine::encoding::{base32, hex};
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams};
use onepass_engine::uri;

use crate::api::dto::{
    EntryDetail, EntryDto, FieldDto, OtpEntryInput, OtpInfoDto, PasswordEntryInput,
};
use crate::api::error::{BridgeError, BridgeResult, ErrorKind};
use crate::session::{lock_session, with_session, SessionState};

/// Offset between the Unix epoch and the .NET epoch (0001-01-01), seconds.
const DOT_NET_OFFSET: i64 = 62_135_596_800;

fn now_dotnet() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + DOT_NET_OFFSET
}

// ---------------------------------------------------------------------------
// Lifecycle

pub(crate) fn core_open(path: &str, password: Zeroizing<Vec<u8>>) -> BridgeResult<Vec<EntryDto>> {
    let data =
        std::fs::read(path).map_err(|e| BridgeError::new(ErrorKind::Io, format!("read {path}: {e}")))?;
    let vault = onepass_engine::db::open(&data, password.as_slice())?;
    let dtos = entries_to_dtos(&vault);

    let mut guard = lock_session();
    if guard.is_some() {
        return Err(BridgeError::new(ErrorKind::SessionState, "a vault is already open".to_string()));
    }
    *guard = Some(SessionState {
        vault,
        password,
        file_path: path.to_string(),
        dirty: false,
    });
    Ok(dtos)
}

pub(crate) fn core_create(
    path: &str,
    name: &str,
    password: Zeroizing<Vec<u8>>,
) -> BridgeResult<()> {
    let vault = Vault::create(name)?;

    let mut guard = lock_session();
    if guard.is_some() {
        return Err(BridgeError::new(ErrorKind::SessionState, "a vault is already open".to_string()));
    }
    *guard = Some(SessionState {
        vault,
        password,
        file_path: path.to_string(),
        dirty: true, // nothing written to disk yet
    });
    Ok(())
}

/// Saves the session vault atomically (temp file + rename, one .bak kept).
/// Returns `false` when there was nothing to save.
pub(crate) fn core_save() -> BridgeResult<bool> {
    let (vault, password, path) = {
        let mut guard = lock_session();
        let s = guard
            .as_mut()
            .ok_or_else(|| BridgeError::new(ErrorKind::SessionState, "vault is locked".to_string()))?;
        if !s.dirty {
            return Ok(false);
        }
        // Clone out of the lock so KDF/encryption never blocks OTP ticks.
        (s.vault.clone(), s.password.clone(), s.file_path.clone())
    };

    let bytes = save_with(&vault, password.as_slice(), &SaveOptions::default())?;
    atomic_write(&path, &bytes)?;

    with_session(|s| {
        s.dirty = false;
        Ok(())
    })?;
    Ok(true)
}

/// Opens a picked `.kdbx` file, validates the password against it, and
/// adopts it as the session vault. `target` becomes the session file path
/// so the next save materializes a fresh copy there; the file on disk at
/// the target is never replaced with an unopenable one.
pub(crate) fn core_import_vault_file(
    path: &str,
    password: Zeroizing<Vec<u8>>,
    target: &str,
) -> BridgeResult<Vec<EntryDto>> {
    let data =
        std::fs::read(path).map_err(|e| BridgeError::new(ErrorKind::Io, format!("read {path}: {e}")))?;
    // Validate against the picked file BEFORE touching the current session:
    // a wrong password must leave the existing vault untouched.
    let vault = onepass_engine::db::open(&data, password.as_slice())?;
    let dtos = entries_to_dtos(&vault);

    // Swap sessions: the old one drops (password zeroized); the new one
    // targets the app vault path so the next save materializes a fresh copy.
    let mut guard = lock_session();
    *guard = Some(SessionState {
        vault,
        password,
        file_path: target.to_string(),
        dirty: true,
    });
    drop(guard);
    Ok(dtos)
}

pub(crate) fn core_lock() -> BridgeResult<()> {
    *lock_session() = None; // SessionState drops: password zeroized
    Ok(())
}

pub(crate) fn core_change_password(new_password: Zeroizing<Vec<u8>>) -> BridgeResult<()> {
    with_session(|s| {
        s.password = new_password;
        s.dirty = true;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Entries

pub(crate) fn core_list_entries() -> BridgeResult<Vec<EntryDto>> {
    with_session(|s| Ok(entries_to_dtos(&s.vault)))
}

pub(crate) fn core_entry_detail(uuid_hex: &str) -> BridgeResult<EntryDetail> {
    with_session(|s| {
        let uuid = decode_uuid(uuid_hex)?;
        let entry = find_in_group(&s.vault.root, &uuid)
            .ok_or_else(|| BridgeError::new(ErrorKind::InvalidParameter, format!("entry {uuid_hex} not found")))?;
        Ok(EntryDetail {
            uuid: uuid_hex.to_string(),
            icon_id: entry.icon_id,
            creation: entry.times.creation,
            last_modification: entry.times.last_modification,
            fields: entry
                .fields
                .iter()
                .map(|f| FieldDto {
                    key: f.key.clone(),
                    // Protected values are never bulk-shipped to Dart.
                    value: if f.protected { String::new() } else { f.value.clone() },
                    protected: f.protected,
                })
                .collect(),
        })
    })
}

pub(crate) fn core_reveal_field(uuid_hex: &str, key: &str) -> BridgeResult<String> {
    with_session(|s| {
        let uuid = decode_uuid(uuid_hex)?;
        let entry = find_in_group(&s.vault.root, &uuid)
            .ok_or_else(|| BridgeError::new(ErrorKind::InvalidParameter, format!("entry {uuid_hex} not found")))?;
        Ok(entry.get(key).unwrap_or("").to_string())
    })
}

pub(crate) fn core_add_password_entry(input: &PasswordEntryInput) -> BridgeResult<String> {
    with_session(|s| {
        let mut entry = new_entry()?;
        entry.set_field(TITLE, &input.title, false);
        entry.set_field(USER_NAME, &input.username, false);
        entry.set_field(PASSWORD, &input.password, true);
        entry.set_field(URL, &input.url, false);
        entry.set_field(NOTES, &input.notes, false);
        Ok(adopt_entry(s, entry))
    })
}

pub(crate) fn core_add_otp_entry(input: &OtpEntryInput) -> BridgeResult<String> {
    with_session(|s| {
        let entry = build_otp_entry(input)?;
        Ok(adopt_entry(s, entry))
    })
}

pub(crate) fn core_update_password_entry(
    uuid_hex: &str,
    input: &PasswordEntryInput,
) -> BridgeResult<()> {
    with_session(|s| {
        let uuid = decode_uuid(uuid_hex)?;
        let entry = find_in_group_mut(&mut s.vault.root, &uuid)
            .ok_or_else(|| BridgeError::new(ErrorKind::InvalidParameter, format!("entry {uuid_hex} not found")))?;
        entry.set_field(TITLE, &input.title, false);
        entry.set_field(USER_NAME, &input.username, false);
        // Empty password means "keep the current one".
        if !input.password.is_empty() {
            entry.set_field(PASSWORD, &input.password, true);
        }
        entry.set_field(URL, &input.url, false);
        entry.set_field(NOTES, &input.notes, false);
        entry.times.last_modification = now_dotnet();
        s.dirty = true;
        Ok(())
    })
}

pub(crate) fn core_update_otp_entry(uuid_hex: &str, input: &OtpEntryInput) -> BridgeResult<()> {
    with_session(|s| {
        let params = otp_params_from_input(input)?;
        let uuid = decode_uuid(uuid_hex)?;
        let entry = find_in_group_mut(&mut s.vault.root, &uuid)
            .ok_or_else(|| BridgeError::new(ErrorKind::InvalidParameter, format!("entry {uuid_hex} not found")))?;
        set_entry_otp(entry, &params)?;
        entry.set_field(TITLE, &otp_title(&params), false);
        if !params.account.is_empty() {
            entry.set_field(USER_NAME, &params.account, false);
        }
        entry.times.last_modification = now_dotnet();
        s.dirty = true;
        Ok(())
    })
}

pub(crate) fn core_delete_entries(uuid_hexes: &[String]) -> BridgeResult<usize> {
    with_session(|s| {
        let mut uuids = Vec::with_capacity(uuid_hexes.len());
        for h in uuid_hexes {
            uuids.push(decode_uuid(h)?);
        }
        let before = count_group(&s.vault.root);
        prune_group(&mut s.vault.root, &uuids);
        let removed = before - count_group(&s.vault.root);
        if removed > 0 {
            s.dirty = true;
        }
        Ok(removed)
    })
}

// ---------------------------------------------------------------------------
// OTP

pub(crate) fn core_otp_info(uuid_hex: &str) -> BridgeResult<Option<OtpInfoDto>> {
    with_session(|s| {
        let uuid = decode_uuid(uuid_hex)?;
        Ok(find_in_group(&s.vault.root, &uuid)
            .and_then(entry_otp)
            .map(|p| OtpInfoDto {
                kind: p.kind.as_str().to_string(),
                issuer: p.issuer.clone(),
                account: p.account.clone(),
                algorithm: p.algorithm.as_str().to_string(),
                digits: p.digits,
                period: p.period,
                counter: p.counter,
                has_pin: p.pin.is_some(),
            }))
    })
}

pub(crate) fn core_otp_code(uuid_hex: &str, time_secs: u64) -> BridgeResult<Option<String>> {
    with_session(|s| {
        let uuid = decode_uuid(uuid_hex)?;
        Ok(find_in_group(&s.vault.root, &uuid)
            .and_then(|e| entry_otp_code(e, time_secs)))
    })
}

// ---------------------------------------------------------------------------
// Import / export

pub(crate) fn core_import_bytes(bytes: &[u8]) -> BridgeResult<Vec<EntryDto>> {
    with_session(|s| {
        let entries = detect_and_import(bytes)?;
        let dtos = entries.iter().map(entry_to_dto).collect();
        s.vault.root.entries.extend(entries);
        s.dirty = true;
        Ok(dtos)
    })
}

pub(crate) fn core_import_otpauth_text(text: &str) -> BridgeResult<Vec<EntryDto>> {
    with_session(|s| {
        let entries = import_otpauth_uris(text)?;
        let dtos = entries.iter().map(entry_to_dto).collect();
        s.vault.root.entries.extend(entries);
        s.dirty = true;
        Ok(dtos)
    })
}

pub(crate) fn core_export_otpauth_text() -> BridgeResult<String> {
    with_session(|s| {
        let refs = otp_entries(&s.vault);
        Ok(export_otpauth_uris(&refs)?)
    })
}

pub(crate) fn core_export_aegis() -> BridgeResult<Vec<u8>> {
    with_session(|s| {
        let refs = otp_entries(&s.vault);
        Ok(export_aegis_json(&refs)?)
    })
}

// ---------------------------------------------------------------------------
// Helpers

fn new_entry() -> BridgeResult<Entry> {
    Ok(Entry {
        uuid: random_bytes(16)?,
        times: Times {
            creation: now_dotnet(),
            last_modification: now_dotnet(),
        },
        ..Default::default()
    })
}

/// Pushes `entry` into the session vault and returns its hex uuid.
fn adopt_entry(s: &mut SessionState, entry: Entry) -> String {
    let uuid = hex::encode(&entry.uuid);
    s.vault.root.entries.push(entry);
    s.dirty = true;
    uuid
}

fn otp_params_from_input(input: &OtpEntryInput) -> BridgeResult<OtpParams> {
    if input.secret_or_uri.trim_start().starts_with("otpauth://") {
        return Ok(uri::parse(input.secret_or_uri.trim())?);
    }
    let secret = base32::decode_tolerant(input.secret_or_uri.trim())
        .map_err(|e| BridgeError::new(ErrorKind::InvalidParameter, format!("invalid base32 secret: {e}")))?;
    Ok(OtpParams {
        kind: OtpKind::parse(&input.kind)?,
        secret,
        algorithm: HashAlgorithm::parse(&input.algorithm)?,
        digits: input.digits,
        period: input.period,
        counter: input.counter,
        pin: if input.pin.is_empty() {
            None
        } else {
            Some(input.pin.clone())
        },
        issuer: input.issuer.clone(),
        account: input.account.clone(),
    })
}

fn build_otp_entry(input: &OtpEntryInput) -> BridgeResult<Entry> {
    let params = otp_params_from_input(input)?;
    let mut entry = entry_from_otp_params(&params)?;
    entry.times = Times {
        creation: now_dotnet(),
        last_modification: now_dotnet(),
    };
    Ok(entry)
}

fn otp_title(params: &OtpParams) -> String {
    if params.issuer.is_empty() {
        params.account.clone()
    } else {
        params.issuer.clone()
    }
}

fn decode_uuid(hex_str: &str) -> BridgeResult<Vec<u8>> {
    hex::decode(hex_str)
        .map_err(|e| BridgeError::new(ErrorKind::InvalidParameter, format!("bad uuid: {e}")))
}

fn find_in_group<'a>(g: &'a Group, uuid: &[u8]) -> Option<&'a Entry> {
    if let Some(e) = g.entries.iter().find(|e| e.uuid == uuid) {
        return Some(e);
    }
    g.groups.iter().find_map(|sg| find_in_group(sg, uuid))
}

fn find_in_group_mut<'a>(g: &'a mut Group, uuid: &[u8]) -> Option<&'a mut Entry> {
    if let Some(e) = g.entries.iter_mut().find(|e| e.uuid == uuid) {
        return Some(e);
    }
    g.groups.iter_mut().find_map(|sg| find_in_group_mut(sg, uuid))
}

fn entries_to_dtos(v: &Vault) -> Vec<EntryDto> {
    let mut out = Vec::new();
    collect_dtos(&v.root, &mut out);
    out
}

fn collect_dtos(g: &Group, out: &mut Vec<EntryDto>) {
    for e in &g.entries {
        out.push(entry_to_dto(e));
    }
    for sg in &g.groups {
        collect_dtos(sg, out);
    }
}

fn entry_to_dto(e: &Entry) -> EntryDto {
    EntryDto {
        uuid: hex::encode(&e.uuid),
        icon_id: e.icon_id,
        title: e.title().unwrap_or("").to_string(),
        username: e.username().unwrap_or("").to_string(),
        url: e.url().unwrap_or("").to_string(),
        notes: e.get(NOTES).unwrap_or("").to_string(),
        has_otp: e.otp().is_some(),
        creation: e.times.creation,
        last_modification: e.times.last_modification,
    }
}

fn count_group(g: &Group) -> usize {
    g.entries.len() + g.groups.iter().map(count_group).sum::<usize>()
}

fn prune_group(g: &mut Group, uuids: &[Vec<u8>]) {
    g.entries.retain(|e| !uuids.contains(&e.uuid));
    for sg in &mut g.groups {
        prune_group(sg, uuids);
    }
}

fn atomic_write(path: &str, bytes: &[u8]) -> BridgeResult<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| BridgeError::new(ErrorKind::Io, format!("write {tmp}: {e}")))?;
    // Keep the previous good file as a one-generation backup.
    let _ = std::fs::rename(path, format!("{path}.bak"));
    std::fs::rename(&tmp, path).map_err(|e| BridgeError::new(ErrorKind::Io, format!("rename {tmp}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session is process-global: serialize tests that use it.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn example_path() -> String {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/example1.kdbx").to_string()
    }

    /// A fresh temp copy of the committed example vault.
    fn temp_copy(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "onepass_bridge_{tag}_{}_{}.kdbx",
            std::process::id(),
            std::thread::current().name().unwrap_or("t")
        ));
        std::fs::copy(example_path(), &p).expect("copy fixture");
        p.to_str().unwrap().to_string()
    }

    fn otp_input(secret_or_uri: &str) -> OtpEntryInput {
        OtpEntryInput {
            issuer: "GitHub".to_string(),
            account: "me@example.com".to_string(),
            secret_or_uri: secret_or_uri.to_string(),
            kind: "totp".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            counter: 0,
            pin: String::new(),
        }
    }

    fn pw_input(title: &str) -> PasswordEntryInput {
        PasswordEntryInput {
            title: title.to_string(),
            username: "user".to_string(),
            password: "hunter2".to_string(),
            url: "https://example.com".to_string(),
            notes: String::new(),
        }
    }

    #[test]
    fn session_lifecycle_end_to_end() {
        let _g = TEST_LOCK.lock().unwrap();
        let _ = core_lock();

        let path = temp_copy("lifecycle");
        let dtos = core_open(&path, Zeroizing::new(b"example1".to_vec())).expect("open");
        assert_eq!(dtos.len(), 2, "fixture has two entries");

        let uuid = core_add_password_entry(&pw_input("Test Site")).expect("add");
        assert_eq!(core_list_entries().unwrap().len(), 3);
        assert!(is_dirty_state());

        // Detail blanks protected values; reveal fetches them on demand.
        let detail = core_entry_detail(&uuid).expect("detail");
        let pw_field = detail.fields.iter().find(|f| f.key == PASSWORD).unwrap();
        assert!(pw_field.protected);
        assert!(pw_field.value.is_empty());
        assert_eq!(core_reveal_field(&uuid, PASSWORD).unwrap(), "hunter2");

        // Save: first call writes, second is a no-op (clean).
        assert!(core_save().unwrap());
        assert!(!core_save().unwrap());

        // Lock, then wrong password is classified correctly.
        core_lock().unwrap();
        assert!(!crate::session::lock_session().is_some());
        assert_eq!(
            core_open(&path, Zeroizing::new(b"nope".to_vec()))
                .unwrap_err()
                .kind,
            ErrorKind::WrongPassword
        );

        // Reopen: the added entry was persisted.
        core_open(&path, Zeroizing::new(b"example1".to_vec())).expect("reopen");
        assert_eq!(core_list_entries().unwrap().len(), 3);
        core_lock().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    #[test]
    fn otp_add_info_code_and_io() {
        let _g = TEST_LOCK.lock().unwrap();
        let _ = core_lock();

        let path = temp_copy("otp");
        core_open(&path, Zeroizing::new(b"example1".to_vec())).expect("open");
        let base = core_list_entries().unwrap().len();

        // Base32 input.
        let uuid_b32 = core_add_otp_entry(&otp_input("JBSWY3DPEHPK3PXP")).expect("add b32");
        let info = core_otp_info(&uuid_b32).unwrap().expect("info");
        assert_eq!(info.kind, "totp");
        assert_eq!(info.issuer, "GitHub");
        assert_eq!(info.algorithm, "SHA1");
        assert!(core_otp_code(&uuid_b32, 59).unwrap().is_some());

        // Full otpauth:// URI input is auto-detected.
        let uuid_uri = core_add_otp_entry(&otp_input(
            "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        ))
        .expect("add uri");

        // Export → import round-trip.
        let text = core_export_otpauth_text().unwrap();
        assert_eq!(text.matches("otpauth://totp/").count(), 2);
        let aegis = core_export_aegis().unwrap();
        assert!(!aegis.is_empty());

        let from_text = core_import_otpauth_text(&text).unwrap();
        assert_eq!(from_text.len(), 2);
        let from_aegis = core_import_bytes(&aegis).unwrap();
        assert_eq!(from_aegis.len(), 2);
        assert_eq!(core_list_entries().unwrap().len(), base + 6);

        // Delete the duplicates and the two added entries.
        let mut doomed: Vec<String> = from_text.into_iter().map(|e| e.uuid).collect();
        doomed.extend(from_aegis.into_iter().map(|e| e.uuid));
        doomed.push(uuid_b32);
        doomed.push(uuid_uri);
        assert_eq!(core_delete_entries(&doomed).unwrap(), 6);
        assert_eq!(core_list_entries().unwrap().len(), base);

        core_lock().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    #[test]
    fn change_password_flow() {
        let _g = TEST_LOCK.lock().unwrap();
        let _ = core_lock();

        let path = temp_copy("chpw");
        core_open(&path, Zeroizing::new(b"example1".to_vec())).expect("open");
        core_change_password(Zeroizing::new(b"brand-new-pw".to_vec())).expect("change");
        assert!(core_save().unwrap());
        core_lock().unwrap();

        assert_eq!(
            core_open(&path, Zeroizing::new(b"example1".to_vec()))
                .unwrap_err()
                .kind,
            ErrorKind::WrongPassword
        );
        core_open(&path, Zeroizing::new(b"brand-new-pw".to_vec())).expect("new pw");
        core_lock().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    #[test]
    fn create_vault_flow() {
        let _g = TEST_LOCK.lock().unwrap();
        let _ = core_lock();

        let path = std::env::temp_dir()
            .join(format!("onepass_create_{}.kdbx", std::process::id()))
            .to_str()
            .unwrap()
            .to_string();
        let _ = std::fs::remove_file(&path);

        core_create(&path, "MyVault", Zeroizing::new(b"pw".to_vec())).expect("create");
        assert!(crate::session::lock_session().is_some());
        core_add_password_entry(&pw_input("First")).expect("add");
        assert!(core_save().unwrap());

        core_lock().unwrap();
        core_open(&path, Zeroizing::new(b"pw".to_vec())).expect("reopen");
        let dtos = core_list_entries().unwrap();
        assert_eq!(dtos.len(), 1);
        assert_eq!(dtos[0].title, "First");
        core_lock().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    fn is_dirty_state() -> bool {
        crate::session::with_session(|s| Ok(s.dirty)).expect("dirty")
    }
}
