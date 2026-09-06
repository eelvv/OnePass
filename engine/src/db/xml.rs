//! KDBX XML data model and parser.
//!
//! Parses the decrypted XML payload into a structured vault. Protected string
//! values are decrypted in document order using the provided inner random
//! stream (Salsa20/ChaCha20).

use base64::Engine;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::db::stream::protected::ProtectedStream;
use crate::error::{Error, Result};

/// A decrypted KDBX vault.
#[derive(Debug, Clone, Default)]
pub struct Vault {
    pub database_name: String,
    pub root: Group,
}

/// A group (folder) of entries and nested groups.
#[derive(Debug, Clone, Default)]
pub struct Group {
    /// 16-byte UUID (opaque, as stored).
    pub uuid: Vec<u8>,
    pub name: String,
    pub notes: String,
    pub entries: Vec<Entry>,
    pub groups: Vec<Group>,
}

/// A single entry (credential + optional 2FA fields).
#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub uuid: Vec<u8>,
    pub icon_id: u32,
    pub fields: Vec<Field>,
}

/// A string field (Title, UserName, Password, URL, Notes, otp, ...).
#[derive(Debug, Clone, Default)]
pub struct Field {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

impl Entry {
    /// Returns the value of a field by key (e.g. "Title", "Password").
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.as_str())
    }

    pub fn title(&self) -> Option<&str> {
        self.get("Title")
    }
    pub fn username(&self) -> Option<&str> {
        self.get("UserName")
    }
    pub fn password(&self) -> Option<&str> {
        self.get("Password")
    }
    pub fn url(&self) -> Option<&str> {
        self.get("URL")
    }
    pub fn otp(&self) -> Option<&str> {
        self.get("otp")
    }
}

/// What the next text node belongs to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Capture {
    None,
    DatabaseName,
    GroupName,
    GroupNotes,
    GroupUuid,
    EntryUuid,
    IconId,
    FieldKey,
    FieldValue { protected: bool },
}

/// Parses the KDBX XML into a [`Vault`].
pub fn parse(xml: &[u8], stream: &mut ProtectedStream) -> Result<Vault> {
    let mut p = Parser {
        stream,
        vault: Vault::default(),
        group_stack: Vec::new(),
        current_entry: None,
        current_field: None,
        in_entry: false,
        capture: Capture::None,
    };

    let mut reader = Reader::from_reader(xml);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => p.start(&e),
            Ok(Event::Empty(e)) => p.empty(&e),
            Ok(Event::Text(e)) => p.text(e.as_ref())?,
            Ok(Event::End(e)) => p.end(e.name().as_ref()),
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Encoding(format!("xml parse: {e}"))),
            _ => {}
        }
    }
    Ok(p.vault)
}

struct Parser<'a> {
    stream: &'a mut ProtectedStream,
    vault: Vault,
    group_stack: Vec<Group>,
    current_entry: Option<Entry>,
    current_field: Option<Field>,
    in_entry: bool,
    capture: Capture,
}

impl Parser<'_> {
    fn start(&mut self, e: &BytesStart) {
        match e.name().as_ref() {
            b"Group" => {
                self.group_stack.push(Group::default());
                self.in_entry = false;
            }
            b"Entry" => {
                self.current_entry = Some(Entry::default());
                self.in_entry = true;
            }
            b"String" => {
                self.current_field = Some(Field::default());
            }
            b"Key" => self.capture = Capture::FieldKey,
            b"Value" => {
                self.capture = Capture::FieldValue {
                    protected: has_protected(e),
                };
            }
            b"DatabaseName" => self.capture = Capture::DatabaseName,
            b"Name" => self.capture = Capture::GroupName,
            b"Notes" => self.capture = Capture::GroupNotes,
            b"UUID" => {
                self.capture = if self.in_entry {
                    Capture::EntryUuid
                } else {
                    Capture::GroupUuid
                };
            }
            b"IconID" => self.capture = Capture::IconId,
            _ => self.capture = Capture::None,
        }
    }

    fn empty(&mut self, e: &BytesStart) {
        // Self-closing leaf elements carry no text. Only Value/Name/Notes
        // need explicit handling (empty string), and only Value can be
        // protected.
        match e.name().as_ref() {
            b"Value" => {
                if let Some(f) = self.current_field.as_mut() {
                    f.protected = has_protected(e);
                }
            }
            b"Name" => {
                if let Some(g) = self.group_stack.last_mut() {
                    g.name.clear();
                }
            }
            b"Notes" => {
                if let Some(g) = self.group_stack.last_mut() {
                    g.notes.clear();
                }
            }
            _ => {}
        }
        self.capture = Capture::None;
    }

    fn text(&mut self, bytes: &[u8]) -> Result<()> {
        match self.capture {
            Capture::None => {}
            Capture::DatabaseName => self.vault.database_name = decode_text(bytes),
            Capture::GroupName => {
                if let Some(g) = self.group_stack.last_mut() {
                    g.name = decode_text(bytes);
                }
            }
            Capture::GroupNotes => {
                if let Some(g) = self.group_stack.last_mut() {
                    g.notes = decode_text(bytes);
                }
            }
            Capture::GroupUuid => {
                if let Some(g) = self.group_stack.last_mut() {
                    g.uuid = decode_base64(bytes);
                }
            }
            Capture::EntryUuid => {
                if let Some(e) = self.current_entry.as_mut() {
                    e.uuid = decode_base64(bytes);
                }
            }
            Capture::IconId => {
                if let Some(e) = self.current_entry.as_mut() {
                    e.icon_id = decode_text(bytes).trim().parse().unwrap_or(0);
                }
            }
            Capture::FieldKey => {
                if let Some(f) = self.current_field.as_mut() {
                    f.key = decode_text(bytes);
                }
            }
            Capture::FieldValue { protected } => {
                if let Some(f) = self.current_field.as_mut() {
                    if protected {
                        let mut plaintext = decode_base64(bytes);
                        self.stream.xor_in_place(&mut plaintext)?;
                        f.value = String::from_utf8_lossy(&plaintext).into_owned();
                        f.protected = true;
                    } else {
                        f.value = decode_text(bytes);
                    }
                }
            }
        }
        self.capture = Capture::None;
        Ok(())
    }

    fn end(&mut self, name: &[u8]) {
        match name {
            b"String" => {
                if let Some(entry) = self.current_entry.as_mut() {
                    if let Some(field) = self.current_field.take() {
                        entry.fields.push(field);
                    }
                }
            }
            b"Entry" => {
                if let Some(entry) = self.current_entry.take() {
                    if let Some(g) = self.group_stack.last_mut() {
                        g.entries.push(entry);
                    }
                }
                self.in_entry = false;
            }
            b"Group" => {
                if let Some(g) = self.group_stack.pop() {
                    if let Some(parent) = self.group_stack.last_mut() {
                        parent.groups.push(g);
                    } else {
                        self.vault.root = g;
                    }
                }
            }
            _ => {}
        }
    }
}

fn has_protected(e: &BytesStart) -> bool {
    e.attributes().flatten().any(|attr| {
        attr.key.as_ref() == b"Protected" && attr.value.as_ref() == b"True"
    })
}

fn decode_text(bytes: &[u8]) -> String {
    xml_unescape(&String::from_utf8_lossy(bytes))
}

fn decode_base64(bytes: &[u8]) -> Vec<u8> {
    let cleaned: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .unwrap_or_default()
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
