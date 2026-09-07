//! TUI application state and logic.

use std::collections::BTreeSet;
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use onepass_engine::db::{
    detect_and_import, entry_from_otp_params, entry_from_otpauth_uri, entry_otp, export_aegis_json,
    export_otpauth_uris, generate_password, otp_entries, random_bytes, save, Entry, Field, Group,
    Vault,
};
use onepass_engine::encoding::base32;
use onepass_engine::otp::{HashAlgorithm, OtpKind, OtpParams, DEFAULT_DIGITS, DEFAULT_PERIOD};

/// Focused panel in Normal mode. Tab cycles between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    List,
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    /// Unified add/edit panel (reused for editing existing entries).
    AddEntry,
    /// Inline single-field edit triggered from Details focus (Enter).
    DetailsEdit,
    Confirm,
    InputPath,
    ChangePassword,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    Import,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Quit,
    /// Delete the highlighted entry (no multi-selection).
    Delete,
    /// Delete every marked entry.
    DeleteMarked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddFormKind {
    Password,
    TwoFa,
}

/// Layout of the unified add/edit form.
///
/// Field 0 is always the **Type** selector (`←`/`→` toggles Password / 2FA).
/// Remaining fields depend on the selected type.
#[derive(Clone, Debug)]
pub struct AddForm {
    /// Set when editing an existing entry; `None` when adding a new one.
    pub editing_uuid: Option<Vec<u8>>,
    pub kind: AddFormKind,
    // -- password fields (indices 1..=5) --
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    // -- 2FA fields (indices 1..=7) --
    pub issuer: String,
    pub account: String,
    /// Base32 secret, or a full `otpauth://` URI (auto-detected on submit).
    pub secret_or_uri: String,
    pub otp_kind: OtpKind,
    pub digits: String,
    pub period: String,
    pub counter: String,
    /// Currently selected field row.
    pub field: usize,
}

impl Default for AddForm {
    fn default() -> Self {
        Self {
            editing_uuid: None,
            kind: AddFormKind::Password,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            issuer: String::new(),
            account: String::new(),
            secret_or_uri: String::new(),
            otp_kind: OtpKind::Totp,
            digits: DEFAULT_DIGITS.to_string(),
            period: DEFAULT_PERIOD.to_string(),
            counter: "0".to_string(),
            field: 0,
        }
    }
}

impl AddForm {
    /// Field 0 (type) is a selector row; the rest are text rows whose count
    /// depends on `kind`. Returns the total number of rows.
    pub fn total_fields(&self) -> usize {
        match self.kind {
            AddFormKind::Password => 6, // type + title/username/password/url/notes
            AddFormKind::TwoFa => 8,    // type + issuer/account/secret/kind/digits/period/counter
        }
    }

    /// Row index of the OTP-kind selector inside a 2FA form, or `None`.
    pub fn otp_kind_row(&self) -> Option<usize> {
        match self.kind {
            AddFormKind::TwoFa => Some(4),
            AddFormKind::Password => None,
        }
    }

    pub fn is_selector_row(&self, row: usize) -> bool {
        row == 0 || self.otp_kind_row() == Some(row)
    }
}

pub struct App {
    pub vault: Vault,
    pub password: String,
    pub file: String,
    pub dirty: bool,
    pub quit: bool,

    pub mode: Mode,
    pub panel: Panel,
    pub filter: String,
    pub selected: usize,
    /// Cursor within the details panel (0 = first field; last = OTP row).
    pub detail_field: usize,
    pub reveal: bool,
    /// Auto-hide deadline for `reveal`.
    pub reveal_until: Option<Instant>,
    /// Multi-selected entry UUIDs (stable across filtering / re-sorting).
    pub marked: BTreeSet<Vec<u8>>,
    pub message: Option<String>,

    pub input: String,
    pub input_action: Option<PathAction>,
    pub confirm: Option<ConfirmAction>,
    pub form: AddForm,
    pub help_scroll: u16,
}

/// Seconds a reveal stays on before auto-hiding.
const REVEAL_SECS: u64 = 15;

impl App {
    pub fn new(vault: Vault, password: String, file: String) -> Self {
        Self {
            vault,
            password,
            file,
            dirty: false,
            quit: false,
            mode: Mode::Normal,
            panel: Panel::List,
            filter: String::new(),
            selected: 0,
            detail_field: 0,
            reveal: false,
            reveal_until: None,
            marked: BTreeSet::new(),
            message: None,
            input: String::new(),
            input_action: None,
            confirm: None,
            form: AddForm::default(),
            help_scroll: 0,
        }
    }

    // -- data access --------------------------------------------------------

    /// Flattened `(group path, entry)` list, narrowed by the current filter.
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

    /// Number of navigable rows in the details panel for the selected entry.
    pub fn details_row_count(&self) -> usize {
        match self.selected_entry() {
            None => 0,
            Some(e) => e.fields.len() + if entry_otp(e).is_some() { 1 } else { 0 },
        }
    }

    fn clamp_selection(&mut self) {
        let len = self.list_len();
        self.selected = if len == 0 {
            0
        } else {
            self.selected.min(len - 1)
        };
        let rows = self.details_row_count();
        self.detail_field = if rows == 0 {
            0
        } else {
            self.detail_field.min(rows - 1)
        };
    }

    // -- keys ---------------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        self.message = None;
        match self.mode {
            Mode::Normal => self.key_normal(key),
            Mode::Search | Mode::InputPath => self.key_text(key),
            Mode::AddEntry => self.key_form(key),
            Mode::Confirm => self.key_confirm(key),
            Mode::DetailsEdit => self.key_details_edit(key),
            Mode::ChangePassword => self.key_change_password(key),
            Mode::Help => self.key_help(key),
        }
        self.tick_reveal();
    }

    fn key_normal(&mut self, key: KeyEvent) {
        // Keys that work in either panel.
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') => return self.request_quit(),
            KeyCode::Char('c') if ctrl => return self.request_quit(),
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                self.help_scroll = 0;
                return;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.panel = match self.panel {
                    Panel::List => Panel::Details,
                    Panel::Details => Panel::List,
                };
                return;
            }
            KeyCode::Char('s') => return self.do_save(),
            KeyCode::Char('P') => {
                self.input.clear();
                self.mode = Mode::ChangePassword;
                return;
            }
            KeyCode::F(5) => {
                self.message = Some("OTP refreshed".to_string());
                if self.reveal {
                    self.reveal_until = Some(Instant::now() + Duration::from_secs(REVEAL_SECS));
                }
                return;
            }
            KeyCode::Char('r') => return self.toggle_reveal(),
            KeyCode::Char('/') => {
                self.input = self.filter.clone();
                self.mode = Mode::Search;
                return;
            }
            KeyCode::Char('i') => {
                self.input.clear();
                self.input_action = Some(PathAction::Import);
                self.mode = Mode::InputPath;
                return;
            }
            KeyCode::Char('e') => {
                self.input.clear();
                self.input_action = Some(PathAction::Export);
                self.mode = Mode::InputPath;
                return;
            }
            _ => {}
        }

        // Clipboard actions target the *selected* entry regardless of panel.
        match key.code {
            KeyCode::Char('u') => return self.copy_field("UserName", "Username"),
            KeyCode::Char('p') => return self.copy_field("Password", "Password"),
            KeyCode::Char('U') => return self.copy_field("URL", "URL"),
            KeyCode::Char('o') => return self.copy_otp_code(),
            _ => {}
        }

        match self.panel {
            Panel::List => self.key_list(key),
            Panel::Details => self.key_details(key),
        }
        self.clamp_selection();
    }

    fn key_list(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.selected += 1,
            KeyCode::Char('k') | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => self.selected = 0,
            KeyCode::Char('G') | KeyCode::End => self.selected = self.list_len().saturating_sub(1),
            KeyCode::Char(' ') => self.toggle_mark(),
            KeyCode::Char('a') => {
                self.form = AddForm::default();
                self.mode = Mode::AddEntry;
            }
            KeyCode::Char('d') => self.request_delete(),
            KeyCode::Enter => {
                // Details focus: open inline single-field edit mode.
                if self.panel == Panel::Details {
                    let Some(entry) = self.selected_entry() else {
                        return;
                    };
                    if self.detail_field < entry.fields.len() {
                        let value = entry.fields[self.detail_field].value.clone();
                        self.input = value;
                        self.mode = Mode::DetailsEdit;
                    } else {
                        // OTP row (not editable inline); just show message.
                        self.message = Some("OTP row: press F5 to refresh".to_string());
                    }
                } else {
                    // List focus: edit the selected entry using the full form.
                    self.begin_edit();
                }
            }
            KeyCode::Esc => {
                self.filter.clear();
            }
            _ => {}
        }
    }

    fn key_details(&mut self, key: KeyEvent) {
        let rows = self.details_row_count();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if rows > 0 {
                    self.detail_field = (self.detail_field + 1) % rows;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if rows > 0 {
                    self.detail_field = (self.detail_field + rows - 1) % rows;
                }
            }
            KeyCode::Char('c') => self.copy_details_row(),
            KeyCode::Char('v') => self.paste_details_row(),
            KeyCode::Enter => self.start_details_edit(),
            KeyCode::Esc => self.panel = Panel::List,
            _ => {}
        }
        self.clamp_selection();
    }

    /// Single-line text input (search = live filter, path = submit on Enter).
    fn key_text(&mut self, key: KeyEvent) {
        match self.mode {
            Mode::Search => match key.code {
                KeyCode::Char(c) => {
                    self.input.push(c);
                    self.filter = self.input.clone();
                    self.selected = 0;
                }
                KeyCode::Backspace => {
                    self.input.pop();
                    self.filter = self.input.clone();
                    self.selected = 0;
                }
                KeyCode::Esc => {
                    // Cancel: restore the previous filter and clear the prompt.
                    self.input.clear();
                    self.filter.clear();
                    self.mode = Mode::Normal;
                }
                KeyCode::Enter => {
                    self.mode = Mode::Normal;
                }
                _ => {}
            },
            Mode::InputPath => match key.code {
                KeyCode::Char(c) => self.input.push(c),
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Enter => {
                    let path = self.input.trim().to_string();
                    let action = self.input_action.take();
                    self.mode = Mode::Normal;
                    if let Some(action) = action {
                        self.run_path_action(action, &path);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        self.clamp_selection();
    }

    fn key_form(&mut self, key: KeyEvent) {
        let total = self.form.total_fields();
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.form.field = (self.form.field + 1) % total,
            KeyCode::BackTab | KeyCode::Up => {
                self.form.field = (self.form.field + total - 1) % total;
            }
            KeyCode::Left if self.form.field == 0 && self.form.editing_uuid.is_none() => {
                self.form.kind = match self.form.kind {
                    AddFormKind::Password => AddFormKind::TwoFa,
                    AddFormKind::TwoFa => AddFormKind::Password,
                }
            }
            KeyCode::Right if self.form.field == 0 && self.form.editing_uuid.is_none() => {
                self.form.kind = match self.form.kind {
                    AddFormKind::Password => AddFormKind::TwoFa,
                    AddFormKind::TwoFa => AddFormKind::Password,
                }
            }
            KeyCode::Left | KeyCode::Right => {
                if self.form.otp_kind_row() == Some(self.form.field) {
                    self.form.otp_kind = cycle_otp_kind(self.form.otp_kind, key.code);
                }
            }
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.form.editing_uuid = None;
            }
            KeyCode::Enter => self.submit_form(),
            KeyCode::Backspace if !self.form.is_selector_row(self.form.field) => {
                self.form_field_mut().pop();
            }
            KeyCode::Char(c) if !self.form.is_selector_row(self.form.field) => {
                self.form_field_mut().push(c);
            }
            _ => {}
        }
    }

    fn submit_form(&mut self) {
        let editing = self.form.editing_uuid.clone();
        let result = match self.form.kind {
            AddFormKind::Password => self.submit_password_form(editing.clone()),
            AddFormKind::TwoFa => self.submit_twofa_form(editing.clone()),
        };
        match result {
            Ok(()) => {
                self.mode = Mode::Normal;
                self.form = AddForm::default();
            }
            Err(e) => self.message = Some(e),
        }
        self.clamp_selection();
    }

    fn submit_password_form(&mut self, editing: Option<Vec<u8>>) -> Result<(), String> {
        let password = if self.form.password.is_empty() {
            generate_password(20).map_err(|e| format!("generate failed: {e}"))?
        } else {
            self.form.password.clone()
        };
        let specs = [
            ("Title", self.form.title.clone(), false),
            ("UserName", self.form.username.clone(), false),
            ("Password", password, true),
            ("URL", self.form.url.clone(), false),
            ("Notes", self.form.notes.clone(), false),
        ];

        match editing {
            Some(uuid) => {
                let entry = find_by_uuid_mut(&mut self.vault.root, &uuid)
                    .ok_or_else(|| "entry not found".to_string())?;
                for (key, value, protected) in specs {
                    set_field(entry, key, &value, protected);
                }
                // Drop optional rows the user cleared.
                entry.fields.retain(|f| {
                    matches!(f.key.as_str(), "Title" | "UserName" | "Password")
                        || !f.value.is_empty()
                });
                self.dirty = true;
                self.message = Some("Entry updated (remember to save)".to_string());
            }
            None => {
                let mut entry = Entry {
                    uuid: random_bytes(16).map_err(|e| format!("random: {e}"))?,
                    ..Default::default()
                };
                for (key, value, protected) in specs {
                    if !value.is_empty() || key == "Title" || key == "UserName" || key == "Password"
                    {
                        entry.fields.push(Field {
                            key: key.to_string(),
                            value,
                            protected,
                        });
                    }
                }
                self.vault.root.entries.push(entry);
                self.dirty = true;
                self.message = Some("Entry added (remember to save)".to_string());
                self.selected = self.list_len().saturating_sub(1);
            }
        }
        Ok(())
    }

    fn submit_twofa_form(&mut self, editing: Option<Vec<u8>>) -> Result<(), String> {
        let entry = build_otp_entry(&self.form)?;
        match editing {
            Some(uuid) => {
                let replaced = replace_by_uuid(&mut self.vault.root, &uuid, entry.clone());
                if replaced {
                    self.dirty = true;
                    self.message = Some("2FA entry updated (remember to save)".to_string());
                }
            }
            None => {
                self.vault.root.entries.push(entry);
                self.dirty = true;
                self.message = Some("2FA entry added (remember to save)".to_string());
                self.selected = self.list_len().saturating_sub(1);
            }
        }
        Ok(())
    }

    fn key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let action = self.confirm.take();
                self.mode = Mode::Normal;
                if let Some(action) = action {
                    self.run_confirm(action);
                }
            }
            _ => {
                self.mode = Mode::Normal;
                self.confirm = None;
            }
        }
        self.clamp_selection();
    }

    /// `P` opens a masked single-field prompt; Enter applies immediately.
    fn key_change_password(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.input.push(c),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                let next = std::mem::take(&mut self.input);
                self.mode = Mode::Normal;
                if next.is_empty() {
                    self.message = Some("Password unchanged".to_string());
                } else {
                    self.password = next;
                    self.dirty = true;
                    self.message = Some(
                        "Master password changed (press s to write it to the file)".to_string(),
                    );
                }
            }
            _ => {}
        }
    }

    fn key_help(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter => self.mode = Mode::Normal,
            KeyCode::Char('q') if self.mode == Mode::Help => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') => {
                self.help_scroll = self.help_scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            _ => {}
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
            ConfirmAction::DeleteMarked => self.do_delete_marked(),
        }
    }

    fn request_delete(&mut self) {
        if self.marked.is_empty() {
            if self.list_len() > 0 {
                self.confirm = Some(ConfirmAction::Delete);
                self.mode = Mode::Confirm;
            }
        } else {
            self.confirm = Some(ConfirmAction::DeleteMarked);
            self.mode = Mode::Confirm;
        }
    }

    fn toggle_mark(&mut self) {
        if let Some(uuid) = self.selected_entry().map(|e| e.uuid.clone()) {
            if !self.marked.remove(&uuid) {
                self.marked.insert(uuid);
            }
            self.message = Some(format!("{} marked", self.marked.len()));
        }
    }

    #[allow(clippy::field_reassign_with_default)]
    fn begin_edit(&mut self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let mut form = AddForm::default();
        form.editing_uuid = Some(entry.uuid.clone());
        for f in &entry.fields {
            match f.key.as_str() {
                "Title" => form.title = f.value.clone(),
                "UserName" => form.username = f.value.clone(),
                "Password" => form.password = f.value.clone(),
                "URL" => form.url = f.value.clone(),
                "Notes" => form.notes = f.value.clone(),
                _ => {}
            }
        }
        if let Some(p) = entry_otp(entry) {
            form.kind = AddFormKind::TwoFa;
            form.issuer = p.issuer.clone();
            form.account = p.account.clone();
            form.secret_or_uri = base32::encode(&p.secret);
            form.otp_kind = p.kind;
            form.digits = p.digits.to_string();
            form.period = p.period.to_string();
            form.counter = p.counter.to_string();
        }
        self.form = form;
        self.mode = Mode::AddEntry;
    }

    /// Details focus: Enter opens inline single-field edit mode.
    fn start_details_edit(&mut self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let _rows = self.details_row_count();
        let value = if self.detail_field < entry.fields.len() {
            entry.fields[self.detail_field].value.clone()
        } else {
            // OTP row (last row) — not editable inline.
            "".to_string()
        };
        self.input = value;
        self.mode = Mode::DetailsEdit;
    }

    fn key_details_edit(&mut self, key: KeyEvent) {
        let Some(entry) = self.selected_entry() else {
            self.mode = Mode::Normal;
            return;
        };
        let field_count = entry.fields.len();
        let field_key = if self.detail_field < field_count {
            entry.fields[self.detail_field].key.clone()
        } else {
            String::new()
        };
        let entry_uuid = entry.uuid.clone();
        match key.code {
            KeyCode::Char(c) => self.input.push(c),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let edited_value = std::mem::take(&mut self.input);
                self.mode = Mode::Normal;
                if self.detail_field >= field_count {
                    self.message = Some("OTP row cannot be edited inline".to_string());
                } else if edited_value.is_empty() {
                    if let Some(e) = find_by_uuid_mut(&mut self.vault.root, &entry_uuid) {
                        if let Some(pos) = e.fields.iter().position(|f| f.key == field_key) {
                            e.fields.remove(pos);
                        }
                    }
                    self.dirty = true;
                    self.message = Some("Field cleared".to_string());
                } else if let Some(e) = find_by_uuid_mut(&mut self.vault.root, &entry_uuid) {
                    if let Some(f) = e.fields.iter_mut().find(|f| f.key == field_key) {
                        f.value = edited_value;
                    }
                    self.dirty = true;
                    self.message = Some("Field updated (remember to save)".to_string());
                }
            }
            KeyCode::Esc => {
                self.input.clear();
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    fn toggle_reveal(&mut self) {
        self.reveal = !self.reveal;
        self.reveal_until = if self.reveal {
            Some(Instant::now() + Duration::from_secs(REVEAL_SECS))
        } else {
            None
        };
    }

    fn tick_reveal(&mut self) {
        if self.reveal {
            if let Some(until) = self.reveal_until {
                if Instant::now() >= until {
                    self.reveal = false;
                    self.reveal_until = None;
                    self.message = Some("Hidden again".to_string());
                }
            }
        }
    }

    fn copy_field(&mut self, key: &str, label: &str) {
        let value = self
            .selected_entry()
            .and_then(|e| e.fields.iter().find(|f| f.key == key))
            .map(|f| f.value.clone());
        match value {
            Some(v) if !v.is_empty() => self.copy_text(&v, label),
            Some(_) => self.message = Some(format!("{label}: empty")),
            None => self.message = Some(format!("{label}: not present")),
        }
    }

    fn copy_otp_code(&mut self) {
        let code = self
            .selected_entry()
            .and_then(entry_otp)
            .and_then(|p| p.generate(now_secs()).ok());
        match code {
            Some(c) => self.copy_text(&c, "OTP code"),
            None => self.message = Some("No OTP on this entry".to_string()),
        }
    }

    fn copy_details_row(&mut self) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let rows = entry.fields.len();
        if self.detail_field < rows {
            let f = &entry.fields[self.detail_field];
            let (key, value) = (f.key.clone(), f.value.clone());
            self.copy_text(&value, &key);
        } else if let Some(p) = entry_otp(entry) {
            match p.generate(now_secs()) {
                Ok(code) => self.copy_text(&code, "OTP code"),
                Err(e) => self.message = Some(format!("OTP failed: {e}")),
            }
        }
    }

    /// Pastes the clipboard into the highlighted details row (writes the field).
    fn paste_details_row(&mut self) {
        let text = match crate::clipboard::paste() {
            Ok(t) => t,
            Err(e) => {
                self.message = Some(e);
                return;
            }
        };
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let rows = entry.fields.len();
        if self.detail_field >= rows {
            self.message = Some("Cannot paste into the OTP row".to_string());
            return;
        }
        let key = entry.fields[self.detail_field].key.clone();
        let uuid = entry.uuid.clone();
        if let Some(e) = find_by_uuid_mut(&mut self.vault.root, &uuid) {
            if let Some(f) = e.fields.iter_mut().find(|f| f.key == key) {
                f.value = text;
                self.dirty = true;
                self.message = Some(format!("{key} replaced from clipboard"));
            }
        }
    }

    fn copy_text(&mut self, text: &str, label: &str) {
        match crate::clipboard::copy(text) {
            Ok(()) => self.message = Some(format!("{label} copied to clipboard")),
            Err(e) => self.message = Some(e),
        }
    }

    fn do_delete(&mut self) {
        if let Some(uuid) = self.selected_entry().map(|e| e.uuid.clone()) {
            if remove_by_uuid(&mut self.vault.root, &uuid).is_some() {
                self.dirty = true;
                self.marked.remove(&uuid);
                self.message = Some("Entry deleted (remember to save)".to_string());
            }
        }
        self.clamp_selection();
    }

    fn do_delete_marked(&mut self) {
        let uuids: Vec<Vec<u8>> = self.marked.iter().cloned().collect();
        let n = uuids.len();
        for uuid in &uuids {
            remove_by_uuid(&mut self.vault.root, uuid);
        }
        self.marked.clear();
        if n > 0 {
            self.dirty = true;
            self.message = Some(format!("Deleted {n} entries (remember to save)"));
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
                if matches!(action, PathAction::Import) {
                    self.dirty = true;
                }
                self.message = Some(msg);
            }
            Err(e) => self.message = Some(format!("{e}")),
        }
        self.clamp_selection();
    }

    fn do_import(&mut self, path: &str) -> Result<String, onepass_engine::Error> {
        let data = fs::read(path)
            .map_err(|e| onepass_engine::Error::Encoding(format!("read {path}: {e}")))?;
        let entries = detect_and_import(&data)?;
        let n = entries.len();
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
        Ok(format!(
            "Imported {n} entries into 'Imported' (remember to save)"
        ))
    }

    fn do_export(&mut self, path: &str) -> Result<String, onepass_engine::Error> {
        let all = otp_entries(&self.vault);
        // Multi-selection narrows the export to the marked entries.
        let entries: Vec<&Entry> = if self.marked.is_empty() {
            all
        } else {
            all.into_iter()
                .filter(|e| self.marked.contains(&e.uuid))
                .collect()
        };
        let data = if path.ends_with(".json") {
            export_aegis_json(&entries)?
        } else {
            export_otpauth_uris(&entries)?.into_bytes()
        };
        fs::write(path, data)
            .map_err(|e| onepass_engine::Error::Encoding(format!("write {path}: {e}")))?;
        let scope = if self.marked.is_empty() {
            "all".to_string()
        } else {
            "marked".to_string()
        };
        Ok(format!(
            "Exported {} OTP entries ({scope}) to {path}",
            entries.len()
        ))
    }
}

// -- helpers ----------------------------------------------------------------

impl App {
    /// Mutable borrow of the text buffer backing the currently selected row.
    fn form_field_mut(&mut self) -> &mut String {
        match self.form.kind {
            AddFormKind::Password => match self.form.field {
                1 => &mut self.form.title,
                2 => &mut self.form.username,
                3 => &mut self.form.password,
                4 => &mut self.form.url,
                _ => &mut self.form.notes,
            },
            AddFormKind::TwoFa => match self.form.field {
                1 => &mut self.form.issuer,
                2 => &mut self.form.account,
                3 => &mut self.form.secret_or_uri,
                5 => &mut self.form.digits,
                6 => &mut self.form.period,
                _ => &mut self.form.counter,
            },
        }
    }
}

/// Seconds remaining in the current TOTP window.
pub fn seconds_remaining(period: u64) -> u64 {
    let now = now_secs();
    if period == 0 {
        0
    } else {
        period - (now % period)
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cycle_otp_kind(current: OtpKind, key: KeyCode) -> OtpKind {
    const ORDER: [OtpKind; 3] = [OtpKind::Totp, OtpKind::Hotp, OtpKind::Steam];
    let pos = ORDER.iter().position(|k| *k == current).unwrap_or(0);
    let next = match key {
        KeyCode::Right => (pos + 1) % ORDER.len(),
        KeyCode::Left => (pos + ORDER.len() - 1) % ORDER.len(),
        _ => pos,
    };
    ORDER[next]
}

/// Builds an entry from the 2FA form: a pasted `otpauth://` URI wins, otherwise
/// the individual rows are combined into params.
fn build_otp_entry(form: &AddForm) -> Result<Entry, String> {
    let raw = form.secret_or_uri.trim().to_string();
    if raw.starts_with("otpauth://") || raw.starts_with("motp://") || raw.contains("://") {
        return entry_from_otpauth_uri(&raw).map_err(|e| format!("{e}"));
    }
    let secret = base32::decode_tolerant(&raw).map_err(|e| format!("secret: {e}"))?;
    if secret.is_empty() {
        return Err("secret is empty".to_string());
    }
    let digits: u32 = if form.digits.trim().is_empty() {
        DEFAULT_DIGITS
    } else {
        form.digits
            .trim()
            .parse()
            .map_err(|_| "digits must be a number".to_string())?
    };
    let period: u64 = if form.period.trim().is_empty() {
        DEFAULT_PERIOD
    } else {
        form.period
            .trim()
            .parse()
            .map_err(|_| "period must be a number".to_string())?
    };
    let counter: u64 = if form.counter.trim().is_empty() {
        0
    } else {
        form.counter
            .trim()
            .parse()
            .map_err(|_| "counter must be a number".to_string())?
    };
    let params = OtpParams {
        kind: form.otp_kind,
        secret,
        algorithm: HashAlgorithm::Sha1,
        digits,
        period,
        counter,
        pin: None,
        issuer: form.issuer.clone(),
        account: form.account.clone(),
    };
    entry_from_otp_params(&params).map_err(|e| format!("{e}"))
}

/// Inserts or updates a field on an entry.
fn set_field(entry: &mut Entry, key: &str, value: &str, protected: bool) {
    if let Some(f) = entry.fields.iter_mut().find(|f| f.key == key) {
        f.value = value.to_string();
        f.protected = protected;
    } else {
        entry.fields.push(Field {
            key: key.to_string(),
            value: value.to_string(),
            protected,
        });
    }
}

fn find_by_uuid_mut<'a>(g: &'a mut Group, uuid: &[u8]) -> Option<&'a mut Entry> {
    if let Some(pos) = g.entries.iter().position(|e| e.uuid == uuid) {
        return Some(&mut g.entries[pos]);
    }
    for sg in &mut g.groups {
        if let Some(e) = find_by_uuid_mut(sg, uuid) {
            return Some(e);
        }
    }
    None
}

fn replace_by_uuid(g: &mut Group, uuid: &[u8], entry: Entry) -> bool {
    if let Some(pos) = g.entries.iter().position(|e| e.uuid == uuid) {
        g.entries[pos] = entry;
        return true;
    }
    for sg in &mut g.groups {
        if replace_by_uuid(sg, uuid, entry.clone()) {
            return true;
        }
    }
    false
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
