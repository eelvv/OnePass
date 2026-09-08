//! In-memory vault session.
//!
//! The decrypted vault and the master password live only on the Rust side;
//! Dart receives DTO copies on demand. Locking drops the session, which
//! zeroizes the password (Vault contents drop with it).

use std::sync::Mutex;
use std::sync::MutexGuard;

use zeroize::Zeroizing;

use onepass_engine::db::Vault;

use crate::api::error::{BridgeError, BridgeResult, ErrorKind};

/// Full unlocked-session state.
pub struct SessionState {
    pub vault: Vault,
    /// Master password used when saving; zeroized on drop.
    pub password: Zeroizing<Vec<u8>>,
    /// Autosave target path.
    pub file_path: String,
    /// True when in-memory state differs from the file on disk.
    pub dirty: bool,
}

/// The process-wide session. `None` = locked.
pub static SESSION: Mutex<Option<SessionState>> = Mutex::new(None);

pub fn lock_session() -> MutexGuard<'static, Option<SessionState>> {
    SESSION.lock().expect("session mutex poisoned")
}

/// Runs `f` with the unlocked session, or fails with [`ErrorKind::SessionState`].
pub fn with_session<T>(f: impl FnOnce(&mut SessionState) -> BridgeResult<T>) -> BridgeResult<T> {
    let mut guard = lock_session();
    match guard.as_mut() {
        Some(s) => f(s),
        None => Err(BridgeError::new(
            ErrorKind::SessionState,
            "vault is locked",
        )),
    }
}
