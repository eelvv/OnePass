//! System clipboard access.

use arboard::Clipboard;

/// Copies text to the system clipboard.
pub fn copy(text: &str) -> Result<(), String> {
    let mut cb = Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    cb.set_text(text.to_string())
        .map_err(|e| format!("clipboard set failed: {e}"))
}

/// Reads the system clipboard, returning its current text contents.
pub fn paste() -> Result<String, String> {
    let mut cb = Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    cb.get_text()
        .map_err(|e| format!("clipboard get failed: {e}"))
}
