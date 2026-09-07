//! TUI application state and logic.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use onepass_engine::db::{
    detect_and_import, entry_from_otp_params, entry_from_otpauth_uri, export_aegis_json,
    export_otpauth_uris, generate_password, otp_entries, random_bytes, save, Entry, Field, Group,
    Vault,
};
use onepass_engine::encoding::base32;
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    AddEntry,
    AddOtp,
    Confirm,
    InputPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    Import,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Quit,
    Delete,
}

#[derive(Default)]
pub struct AddForm {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub field: usize, // 0..=4
}

pub struct App {
    pub vault: Vault,
    pub password: String,
    pub file: String,
    pub dirty: bool,
    pub quit: bool,

    pub mode: Mode,
    pub filter: String,
    pub selected: usize,
    pub reveal: bool,
    pub message: Option<String>,

    pub input: String,
    pub input_action: Option<PathAction>,
    pub confirm: Option<ConfirmAction>,
    pub form: AddForm,
}

impl App {
    pub fn new(vault: Vault, password: String, file: String) -> Self {
        Self {
            vault,
            password,
            file,
            dirty: false,
            quit: false,
            mode: Mode::Normal,
            filter: String::new(),
            selected: 0,
            reveal: false,
            message: None,
            input: String::new(),
            input_action: None,
            confirm: None,
            form: AddForm::default(),
        }
    }

    // -- data access --------------------------------------------------------

    /// Flattened (group path, entry) list, filtered by the current filter.
    pub fn filtered_entries(&self) -> Vec<(String, &Entry)> {
        let mut out = Vec::new();
        collect(&self.vault.root, "", &mut out);
        if self.filter.is_empty() {
            return out;
        }
        let f = self.filter.to_lowercase();
        out.into_iter()
            .filter(|(_, e)| {
                e.title().unwrap_or("").to_lowercase().contains(&f)
                    || e.username().unwrap_or("").to_lowercase().contains(&f)
            })
            .collect()
    }

    pub fn list_len(&self) -> usize {
        self.filtered_entries().len()
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.filtered_entries().get(self.selected).map(|(_, e)| *e)
    }

    fn clamp_selection(&mut self) {
        let len = self.list_len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    // -- keys ---------------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        self.message = None;
        match self.mode {
            Mode::Normal => self.key_normal(key),
            Mode::Search | Mode::AddOtp | Mode::InputPath => self.key_text(key),
            Mode::AddEntry => self.key_form(key),
            Mode::Confirm => self.key_confirm(key),
        }
    }

    fn key_normal(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('c') if ctrl => self.request_quit(),
            KeyCode::Char('j') | KeyCode::Down => self.selected += 1,
            KeyCode::Char('k') | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => self.selected = 0,
            KeyCode::Char('G') | KeyCode::End => self.selected = self.list_len().saturating_sub(1),
            KeyCode::Char('s') => self.do_save(),
            KeyCode::Char('a') => {
                self.form = AddForm::default();
                self.mode = Mode::AddEntry;
            }
            KeyCode::Char('t') => {
                self.input.clear();
                self.mode = Mode::AddOtp;
            }
            KeyCode::Char('d') => {
                if self.list_len() > 0 {
                    self.confirm = Some(ConfirmAction::Delete);
                    self.mode = Mode::Confirm;
                }
            }
            KeyCode::Char('/') => {
                self.input.clear();
                self.mode = Mode::Search;
            }
            KeyCode::Char('i') => {
                self.input.clear();
                self.input_action = Some(PathAction::Import);
                self.mode = Mode::InputPath;
            }
            KeyCode::Char('e') => {
                self.input.clear();
                self.input_action = Some(PathAction::Export);
                self.mode = Mode::InputPath;
            }
            KeyCode::Char('r') => self.reveal = !self.reveal,
            KeyCode::Esc => self.filter.clear(),
            _ => {}
        }
        self.clamp_selection();
    }

    /// Single-line text input modes (search / OTP URI / file path).
    fn key_text(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.input.push(c),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => self.submit_text(),
            _ => {}
        }
    }

    fn submit_text(&mut self) {
        match self.mode {
            Mode::Search => {
                self.filter = self.input.clone();
                self.mode = Mode::Normal;
                self.clamp_selection();
            }
            Mode::AddOtp => {
                let uri = self.input.trim().to_string();
                match entry_from_otpauth_uri(&uri) {
                    Ok(entry) => {
                        self.vault.root.entries.push(entry);
                        self.dirty = true;
                        self.message = Some("OTP entry added (remember to save)".to_string());
                    }
                    Err(e) => self.message = Some(format!("Failed: {e}")),
                }
                self.mode = Mode::Normal;
            }
            Mode::InputPath => {
                let path = self.input.trim().to_string();
                let action = self.input_action;
                self.mode = Mode::Normal;
                if let Some(action) = action {
                    self.run_path_action(action, &path);
                }
            }
            _ => {}
        }
    }

    fn key_form(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.form.field = (self.form.field + 1) % 5,
            KeyCode::Up | KeyCode::BackTab => self.form.field = (self.form.field + 4) % 5,
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => self.submit_form(),
            KeyCode::Backspace => {
                field_mut(&mut self.form).pop();
            }
            KeyCode::Char(c) => field_mut(&mut self.form).push(c),
            _ => {}
        }
    }

    fn submit_form(&mut self) {
        let password = if self.form.password.is_empty() {
            match generate_password(20) {
                Ok(p) => p,
                Err(e) => {
                    self.message = Some(format!("generate failed: {e}"));
                    return;
                }
            }
        } else {
            self.form.password.clone()
        };
        let mut entry = Entry {
            uuid: match random_bytes(16) {
                Ok(u) => u,
                Err(e) => {
                    self.message = Some(format!("random: {e}"));
                    return;
                }
            },
            ..Default::default()
        };
        entry.fields.push(Field {
            key: "Title".to_string(),
            value: self.form.title.clone(),
            protected: false,
        });
        entry.fields.push(Field {
            key: "UserName".to_string(),
            value: self.form.username.clone(),
            protected: false,
        });
        entry.fields.push(Field {
            key: "Password".to_string(),
            value: password,
            protected: true,
        });
        if !self.form.url.is_empty() {
            entry.fields.push(Field {
                key: "URL".to_string(),
                value: self.form.url.clone(),
                protected: false,
            });
        }
        if !self.form.notes.is_empty() {
            entry.fields.push(Field {
                key: "Notes".to_string(),
                value: self.form.notes.clone(),
                protected: false,
            });
        }

        self.vault.root.entries.push(entry);
        self.dirty = true;
        self.message = Some("Entry added (remember to save)".to_string());
        self.mode = Mode::Normal;
        self.selected = self.list_len().saturating_sub(1);
    }

    fn key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let action = self.confirm;
                self.mode = Mode::Normal;
                self.confirm = None;
                if let Some(action) = action {
                    self.run_confirm(action);
                }
            }
            _ => {
                self.mode = Mode::Normal;
                self.confirm = None;
            }
        }
    }

    // -- actions ------------------------------------------------------------

    fn request_quit(&mut self) {
        if self.dirty {
            self.confirm = Some(ConfirmAction::Quit);
            self.mode = Mode::Confirm;
        } else {
            self.quit = true;
        }
    }

    fn run_confirm(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::Quit => self.quit = true,
            ConfirmAction::Delete => self.do_delete(),
        }
    }

    fn do_delete(&mut self) {
        let target = self
            .filtered_entries()
            .get(self.selected)
            .map(|(_, e)| e.uuid.clone());
        if let Some(uuid) = target {
            if remove_by_uuid(&mut self.vault.root, &uuid).is_some() {
                self.dirty = true;
                self.message = Some("Entry deleted (remember to save)".to_string());
            }
        }
        self.clamp_selection();
    }

    pub fn do_save(&mut self) {
        match save(&self.vault, self.password.as_bytes()) {
            Ok(bytes) => match fs::write(&self.file, bytes) {
                Ok(()) => {
                    self.dirty = false;
                    self.message = Some(format!("Saved to {}", self.file));
                }
                Err(e) => self.message = Some(format!("write failed: {e}")),
            },
            Err(e) => self.message = Some(format!("save failed: {e}")),
        }
    }

    fn run_path_action(&mut self, action: PathAction, path: &str) {
        if path.is_empty() {
            return;
        }
        let result = match action {
            PathAction::Import => self.do_import(path),
            PathAction::Export => self.do_export(path),
        };
        match result {
            Ok(msg) => {
                self.dirty = true;
                self.message = Some(msg);
            }
            Err(e) => self.message = Some(format!("{e}")),
        }
    }

    fn do_import(&mut self, path: &str) -> Result<String, onepass_engine::Error> {
        let data = fs::read(path)
            .map_err(|e| onepass_engine::Error::Encoding(format!("read {path}: {e}")))?;
        let entries = detect_and_import(&data)?;
        let n = entries.len();

        // Find or create an "Imported" group.
        if let Some(g) = self
            .vault
            .root
            .groups
            .iter_mut()
            .find(|g| g.name == "Imported")
        {
            g.entries.extend(entries);
        } else {
            let mut g = Group {
                uuid: random_bytes(16)?,
                name: "Imported".to_string(),
                ..Default::default()
            };
            g.entries = entries;
            self.vault.root.groups.push(g);
        }
        self.clamp_selection();
        Ok(format!(
            "Imported {n} entries into 'Imported' (remember to save)"
        ))
    }

    fn do_export(&mut self, path: &str) -> Result<String, onepass_engine::Error> {
        let entries = otp_entries(&self.vault);
        let refs: Vec<&Entry> = entries.iter().copied().collect();
        let data = if path.ends_with(".json") {
            export_aegis_json(&refs)?
        } else {
            export_otpauth_uris(&refs)?.into_bytes()
        };
        fs::write(path, data)
            .map_err(|e| onepass_engine::Error::Encoding(format!("write {path}: {e}")))?;
        Ok(format!("Exported {} OTP entries to {path}", refs.len()))
    }

    /// Adds an OTP entry from a pasted otpauth URI (used by the AddOtp mode).
    #[allow(dead_code)]
    fn add_otp_manual(
        &mut self,
        issuer: &str,
        account: &str,
        secret_b32: &str,
        kind: OtpKind,
        digits: u32,
        period: u64,
        counter: u64,
    ) -> Result<(), onepass_engine::Error> {
        let params = OtpParams {
            kind,
            secret: base32::decode_tolerant(secret_b32)?,
            algorithm: HashAlgorithm::Sha1,
            digits,
            period,
            counter,
            pin: None,
            issuer: issuer.to_string(),
            account: account.to_string(),
        };
        let entry = entry_from_otp_params(&params)?;
        self.vault.root.entries.push(entry);
        self.dirty = true;
        Ok(())
    }
}

// -- helpers ----------------------------------------------------------------

/// Seconds remaining in the current TOTP window.
pub fn seconds_remaining(period: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if period == 0 {
        0
    } else {
        period - (now % period)
    }
}

fn field_mut(form: &mut AddForm) -> &mut String {
    match form.field {
        0 => &mut form.title,
        1 => &mut form.username,
        2 => &mut form.password,
        3 => &mut form.url,
        _ => &mut form.notes,
    }
}

fn remove_by_uuid(g: &mut Group, uuid: &[u8]) -> Option<Entry> {
    if let Some(pos) = g.entries.iter().position(|e| e.uuid == uuid) {
        return Some(g.entries.remove(pos));
    }
    for sg in &mut g.groups {
        if let Some(e) = remove_by_uuid(sg, uuid) {
            return Some(e);
        }
    }
    None
}

fn collect<'a>(g: &'a Group, path: &str, out: &mut Vec<(String, &'a Entry)>) {
    for e in &g.entries {
        out.push((path.to_string(), e));
    }
    for sg in &g.groups {
        let p = if path.is_empty() {
            sg.name.clone()
        } else {
            format!("{path}/{}", sg.name)
        };
        collect(sg, &p, out);
    }
}
