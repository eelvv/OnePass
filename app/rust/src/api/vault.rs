//! FRB-visible vault API: thin wrappers over `crate::logic`.
//!
//! Heavy operations (KDF, crypto, import/export) are `async` and run on the
//! FRB worker pool so the UI isolate never blocks; only trivial getters are
//! `#[frb(sync)]`.

use zeroize::Zeroizing;

use super::dto::{
    EntryDetail, EntryDto, OtpEntryInput, OtpInfoDto, PasswordEntryInput, PasswordPolicyDto,
};
use super::error::BridgeResult;
use crate::logic;

// ---------------------------------------------------------------------------
// Lifecycle

/// Opens (decrypts) the vault file and starts a session.
pub async fn open_vault(path: String, password: Vec<u8>) -> BridgeResult<Vec<EntryDto>> {
    logic::core_open(&path, Zeroizing::new(password))
}

/// Creates a new vault in memory. Call `save_session` to write it to disk.
pub async fn create_vault(path: String, name: String, password: Vec<u8>) -> BridgeResult<()> {
    logic::core_create(&path, &name, Zeroizing::new(password))
}

/// Encrypts and writes the session vault. Returns `false` when clean.
pub async fn save_session() -> BridgeResult<bool> {
    logic::core_save()
}

/// Drops the session (password zeroized on the Rust side).
pub async fn lock_vault() -> BridgeResult<()> {
    logic::core_lock()
}

/// Replaces the master password used for the next save.
pub async fn change_master_password(new_password: Vec<u8>) -> BridgeResult<()> {
    logic::core_change_password(Zeroizing::new(new_password))
}

/// Whether a vault session is currently unlocked.
#[flutter_rust_bridge::frb(sync)]
pub fn is_unlocked() -> bool {
    crate::session::lock_session().is_some()
}

/// Whether the unlocked session has unsaved changes (false when locked).
#[flutter_rust_bridge::frb(sync)]
pub fn is_dirty() -> BridgeResult<bool> {
    crate::session::with_session(|s| Ok(s.dirty))
}

// ---------------------------------------------------------------------------
// Entries

pub async fn list_entries() -> BridgeResult<Vec<EntryDto>> {
    logic::core_list_entries()
}

/// Full entry for the detail view (protected values blanked).
pub async fn entry_detail(uuid_hex: String) -> BridgeResult<EntryDetail> {
    logic::core_entry_detail(&uuid_hex)
}

/// Fetches one field value on demand (e.g. the password).
pub async fn reveal_field(uuid_hex: String, key: String) -> BridgeResult<String> {
    logic::core_reveal_field(&uuid_hex, &key)
}

/// Adds a password entry, returning its hex uuid.
pub async fn add_password_entry(input: PasswordEntryInput) -> BridgeResult<String> {
    logic::core_add_password_entry(&input)
}

/// Adds a 2FA entry, returning its hex uuid.
pub async fn add_otp_entry(input: OtpEntryInput) -> BridgeResult<String> {
    logic::core_add_otp_entry(&input)
}

pub async fn update_password_entry(uuid_hex: String, input: PasswordEntryInput) -> BridgeResult<()> {
    logic::core_update_password_entry(&uuid_hex, &input)
}

pub async fn update_otp_entry(uuid_hex: String, input: OtpEntryInput) -> BridgeResult<()> {
    logic::core_update_otp_entry(&uuid_hex, &input)
}

/// Removes entries (and any nested ones), returning how many were deleted.
pub async fn delete_entries(uuid_hexes: Vec<String>) -> BridgeResult<usize> {
    logic::core_delete_entries(&uuid_hexes)
}

// ---------------------------------------------------------------------------
// OTP

/// Parsed OTP configuration of an entry, if any.
pub async fn otp_info(uuid_hex: String) -> BridgeResult<Option<OtpInfoDto>> {
    logic::core_otp_info(&uuid_hex)
}

/// Current OTP code at `time_secs` (unix seconds); cheap enough for 1s ticks.
#[flutter_rust_bridge::frb(sync)]
pub fn otp_code(uuid_hex: String, time_secs: u64) -> BridgeResult<Option<String>> {
    logic::core_otp_code(&uuid_hex, time_secs)
}

// ---------------------------------------------------------------------------
// Import / export

/// Auto-detects the format (Aegis JSON / Google migration / URI list) and
/// appends the imported entries to the vault root.
pub async fn import_from_bytes(bytes: Vec<u8>) -> BridgeResult<Vec<EntryDto>> {
    logic::core_import_bytes(&bytes)
}

/// Imports a text list of `otpauth://` URIs.
pub async fn import_from_otpauth_text(text: String) -> BridgeResult<Vec<EntryDto>> {
    logic::core_import_otpauth_text(&text)
}

/// Exports all 2FA entries as an `otpauth://` URI list.
pub async fn export_otpauth_text() -> BridgeResult<String> {
    logic::core_export_otpauth_text()
}

/// Exports all 2FA entries as Aegis JSON.
pub async fn export_aegis() -> BridgeResult<Vec<u8>> {
    logic::core_export_aegis()
}

// ---------------------------------------------------------------------------
// Generator

#[flutter_rust_bridge::frb(sync)]
pub fn generate_password(len: u32, policy: PasswordPolicyDto) -> BridgeResult<String> {
    Ok(onepass_engine::db::generate_password_with_policy(
        len as usize,
        &onepass_engine::db::PasswordPolicy {
            upper: policy.upper,
            lower: policy.lower,
            digits: policy.digits,
            symbols: policy.symbols,
            exclude_ambiguous: policy.exclude_ambiguous,
            require_each_set: policy.require_each_set,
        },
    )?)
}
