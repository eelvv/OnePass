//! KDBX XML data model and parser.
//!
//! Parses the decrypted XML payload into a structured vault. Protected string
//! values are decrypted in document order using the provided inner random
//! stream (Salsa20/ChaCha20).

use base64::Engine;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::db::inner_header::InnerBinary;
use crate::db::random_bytes;
use crate::db::stream::protected::ProtectedStream;
use crate::error::{Error, Result};

/// Metadata constructs that were present in the parsed file but are **not**
/// preserved by this data model, i.e. what a save would drop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LossReport {
    /// Previous entry revisions inside `<History>` (skipped, not merged).
    pub history_entries: usize,
    /// Entry attachment references (`<Binary Ref>` under entry `<Binaries>`);
    /// the referenced inner-header blobs are kept, but the entry-level link
    /// is not round-tripped.
    pub binary_refs: usize,
    /// `<CustomData><Item>` records (file / group / entry level).
    pub custom_data: usize,
    /// `<DeletedObjects><DeletedObject>` records.
    pub deleted_objects: usize,
    /// Inner-header attachments that are encrypted with the inner random
    /// stream. They cannot be carried over: each save regenerates the stream
    /// key, and the bytes would silently stop decrypting, so they are
    /// dropped and reported instead.
    pub protected_binaries: usize,
}

impl LossReport {
    pub fn is_empty(&self) -> bool {
        self.history_entries == 0
            && self.binary_refs == 0
            && self.custom_data == 0
            && self.deleted_objects == 0
            && self.protected_binaries == 0
    }

    /// One-line human-readable summary, e.g. `"2 history item(s), 1
    /// attachment reference(s)"`. Empty string when nothing is lost.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.history_entries > 0 {
            parts.push(format!("{} history item(s)", self.history_entries));
        }
        if self.binary_refs > 0 {
            parts.push(format!("{} attachment reference(s)", self.binary_refs));
        }
        if self.protected_binaries > 0 {
            parts.push(format!(
                "{} stream-encrypted attachment(s)",
                self.protected_binaries
            ));
        }
        if self.custom_data > 0 {
            parts.push(format!("{} custom-data item(s)", self.custom_data));
        }
        if self.deleted_objects > 0 {
            parts.push(format!("{} deleted-object record(s)", self.deleted_objects));
        }
        parts.join(", ")
    }
}

/// A decrypted KDBX vault.
#[derive(Debug, Clone, Default)]
pub struct Vault {
    pub database_name: String,
    pub root: Group,
    /// Unprotected binary attachments from the KDBX 4 inner header, carried
    /// over verbatim across open → save. Stream-encrypted ones are reported
    /// in [`Vault::losses`] instead (their bytes would stop decrypting once
    /// the inner stream key is regenerated).
    pub binaries: Vec<InnerBinary>,
    /// What the source file contained that this model does not preserve.
    pub losses: LossReport,
}

impl Vault {
    /// Creates a new empty vault with a fresh root group UUID.
    pub fn create(database_name: &str) -> Result<Self> {
        Ok(Self {
            database_name: database_name.to_string(),
            root: Group {
                uuid: random_bytes(16)?,
                ..Default::default()
            },
            ..Default::default()
        })
    }
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
    pub times: Times,
    pub fields: Vec<Field>,
}

/// Entry timestamps as stored by KeePass (seconds in the .NET epoch).
///
/// Zero means "unknown"; such values are rewritten as "now" on save.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Times {
    pub creation: i64,
    pub last_modification: i64,
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

    /// Sets (or adds) a field by key, replacing value and protected flag.
    pub fn set_field(&mut self, key: &str, value: &str, protected: bool) {
        if let Some(f) = self.fields.iter_mut().find(|f| f.key == key) {
            f.value = value.to_string();
            f.protected = protected;
        } else {
            self.fields.push(Field {
                key: key.to_string(),
                value: value.to_string(),
                protected,
            });
        }
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
    CreationTime,
    LastModificationTime,
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
        in_entry_times: false,
        in_history: false,
        in_custom_data: false,
        in_deleted: false,
        losses: LossReport::default(),
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
    p.vault.losses = p.losses;
    Ok(p.vault)
}

struct Parser<'a> {
    stream: &'a mut ProtectedStream,
    vault: Vault,
    group_stack: Vec<Group>,
    current_entry: Option<Entry>,
    current_field: Option<Field>,
    in_entry: bool,
    in_entry_times: bool,
    /// Inside an entry's `<History>` block (previous revisions).
    in_history: bool,
    /// Inside a `<CustomData>` map (meta, group, or entry level).
    in_custom_data: bool,
    /// Inside the root `<DeletedObjects>` list.
    in_deleted: bool,
    /// Constructs seen in the document but not representable in [`Vault`].
    losses: LossReport,
    capture: Capture,
}

impl Parser<'_> {
    fn start(&mut self, e: &BytesStart) {
        // Inside <History> every nested element belongs to a previous entry
        // revision. The model has no place for history; parsing it naively is
        // worse than dropping it — the nested </Entry> would push the
        // revision as a real entry and clear the live one, so opening a
        // KeePass file with history would REPLACE every entry by its first
        // revision. Skip the whole block and count what was skipped.
        if self.in_history {
            if e.name().as_ref() == b"Entry" {
                self.losses.history_entries += 1;
            }
            return;
        }
        if self.in_custom_data {
            if e.name().as_ref() == b"Item" {
                self.losses.custom_data += 1;
            }
            return;
        }
        if self.in_deleted {
            if e.name().as_ref() == b"DeletedObject" {
                self.losses.deleted_objects += 1;
            }
            return;
        }

        match e.name().as_ref() {
            b"History" if self.in_entry => self.in_history = true,
            b"CustomData" => self.in_custom_data = true,
            b"DeletedObjects" => self.in_deleted = true,
            b"Binary" if self.in_entry => self.losses.binary_refs += 1,
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
            b"Times" if self.in_entry => self.in_entry_times = true,
            b"CreationTime" if self.in_entry_times => self.capture = Capture::CreationTime,
            b"LastModificationTime" if self.in_entry_times => {
                self.capture = Capture::LastModificationTime
            }
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
            Capture::CreationTime => {
                if let Some(e) = self.current_entry.as_mut() {
                    e.times.creation = decode_date(bytes);
                }
            }
            Capture::LastModificationTime => {
                if let Some(e) = self.current_entry.as_mut() {
                    e.times.last_modification = decode_date(bytes);
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
        // Leave the skip-contexts first; everything nested inside them was
        // already counted in `start` and must not reach the state machine.
        if self.in_history {
            if name == b"History" {
                self.in_history = false;
            }
            return;
        }
        if self.in_custom_data {
            if name == b"CustomData" {
                self.in_custom_data = false;
            }
            return;
        }
        if self.in_deleted {
            if name == b"DeletedObjects" {
                self.in_deleted = false;
            }
            return;
        }

        match name {
            b"Times" => self.in_entry_times = false,
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
    e.attributes()
        .flatten()
        .any(|attr| attr.key.as_ref() == b"Protected" && attr.value.as_ref() == b"True")
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

/// Decodes a KeePass date (8-byte little-endian .NET epoch seconds, base64).
fn decode_date(bytes: &[u8]) -> i64 {
    let v = decode_base64(bytes);
    if v.len() == 8 {
        i64::from_le_bytes(v.try_into().expect("len checked above"))
    } else {
        0
    }
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ---------------------------------------------------------------------------
// Serialization

use std::time::{SystemTime, UNIX_EPOCH};

/// Offset between the Unix epoch (1970-01-01) and the .NET epoch (0001-01-01),
/// in seconds.
const DOT_NET_OFFSET: i64 = 62_135_596_800;

/// Serializes a [`Vault`] into KDBX 4.x XML, protecting marked fields.
pub fn serialize(
    vault: &Vault,
    stream: &mut ProtectedStream,
    header_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut s = String::with_capacity(4096);
    s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n");
    s.push_str("<KeePassFile>\n");
    write_meta(&mut s, vault, header_hash);
    s.push_str("<Root>\n");
    write_group(&mut s, &vault.root, stream)?;
    s.push_str("<DeletedObjects/>\n");
    s.push_str("</Root>\n");
    s.push_str("</KeePassFile>\n");
    Ok(s.into_bytes())
}

fn write_meta(s: &mut String, vault: &Vault, header_hash: &[u8; 32]) {
    let now = dotnet_now();
    s.push_str("<Meta>\n");
    write_str_elem(s, "Generator", "OnePass");
    write_b64_elem(s, "HeaderHash", header_hash);
    write_str_elem(s, "DatabaseName", &vault.database_name);
    write_date(s, "DatabaseNameChanged", now);
    s.push_str("<DatabaseDescription/>\n");
    write_date(s, "DatabaseDescriptionChanged", now);
    s.push_str("<DefaultUserName/>\n");
    write_date(s, "DefaultUserNameChanged", now);
    s.push_str("<MaintenanceHistoryDays>365</MaintenanceHistoryDays>\n");
    s.push_str("<Color/>\n");
    write_date(s, "MasterKeyChanged", now);
    s.push_str("<MasterKeyChangeRec>-1</MasterKeyChangeRec>\n");
    s.push_str("<MasterKeyChangeForce>-1</MasterKeyChangeForce>\n");
    s.push_str("<MemoryProtection>\n");
    s.push_str("<ProtectTitle>False</ProtectTitle>\n");
    s.push_str("<ProtectUserName>False</ProtectUserName>\n");
    s.push_str("<ProtectPassword>True</ProtectPassword>\n");
    s.push_str("<ProtectURL>False</ProtectURL>\n");
    s.push_str("<ProtectNotes>False</ProtectNotes>\n");
    s.push_str("</MemoryProtection>\n");
    s.push_str("<CustomData/>\n");
    s.push_str("</Meta>\n");
}

fn write_group(s: &mut String, g: &Group, stream: &mut ProtectedStream) -> Result<()> {
    s.push_str("<Group>\n");
    write_b64_elem(s, "UUID", &g.uuid);
    write_str_elem(s, "Name", &g.name);
    if g.notes.is_empty() {
        s.push_str("<Notes/>\n");
    } else {
        write_str_elem(s, "Notes", &g.notes);
    }
    write_u32_elem(s, "IconID", 48);
    write_times(s, &Times::default());
    s.push_str("<IsExpanded>True</IsExpanded>\n");
    for e in &g.entries {
        write_entry(s, e, stream)?;
    }
    for sg in &g.groups {
        write_group(s, sg, stream)?;
    }
    s.push_str("</Group>\n");
    Ok(())
}

fn write_entry(s: &mut String, e: &Entry, stream: &mut ProtectedStream) -> Result<()> {
    s.push_str("<Entry>\n");
    write_b64_elem(s, "UUID", &e.uuid);
    write_u32_elem(s, "IconID", e.icon_id);
    s.push_str("<ForegroundColor/>\n");
    s.push_str("<BackgroundColor/>\n");
    s.push_str("<OverrideURL/>\n");
    s.push_str("<Tags/>\n");
    write_times(s, &e.times);
    for f in &e.fields {
        s.push_str("<String>\n");
        write_str_elem(s, "Key", &f.key);
        s.push_str("<Value");
        if f.protected {
            s.push_str(" Protected=\"True\"");
        }
        s.push('>');
        if f.protected {
            let mut data = f.value.as_bytes().to_vec();
            stream.xor_in_place(&mut data)?;
            s.push_str(&b64(&data));
        } else {
            s.push_str(&esc(&f.value));
        }
        s.push_str("</Value>\n");
        s.push_str("</String>\n");
    }
    s.push_str(
        "<AutoType>\n<Enabled>True</Enabled>\n<DataTransferObfuscation>0</DataTransferObfuscation>\n<DefaultSequence/>\n</AutoType>\n",
    );
    s.push_str("<History/>\n");
    s.push_str("</Entry>\n");
    Ok(())
}

fn write_times(s: &mut String, times: &Times) {
    let now = dotnet_now();
    let creation = if times.creation == 0 {
        now
    } else {
        times.creation
    };
    let last_modification = if times.last_modification == 0 {
        now
    } else {
        times.last_modification
    };
    s.push_str("<Times>\n");
    write_date(s, "LastModificationTime", last_modification);
    write_date(s, "CreationTime", creation);
    write_date(s, "LastAccessTime", now);
    write_date(s, "ExpiryTime", now);
    s.push_str("<Expires>False</Expires>\n");
    s.push_str("<UsageCount>0</UsageCount>\n");
    write_date(s, "LocationChanged", now);
    s.push_str("</Times>\n");
}

fn dotnet_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + DOT_NET_OFFSET
}

fn write_date(s: &mut String, tag: &str, dotnet_secs: i64) {
    write_b64_elem(s, tag, &dotnet_secs.to_le_bytes());
}

fn write_str_elem(s: &mut String, tag: &str, value: &str) {
    s.push_str(&format!("<{tag}>{}</{tag}>\n", esc(value)));
}

fn write_b64_elem(s: &mut String, tag: &str, bytes: &[u8]) {
    s.push_str(&format!("<{tag}>{}</{tag}>\n", b64(bytes)));
}

fn write_u32_elem(s: &mut String, tag: &str, value: u32) {
    s.push_str(&format!("<{tag}>{value}</{tag}>\n"));
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ProtectedStreamKind;

    fn parse_str(xml: &str) -> Vault {
        let mut stream = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &[0x42u8; 32]);
        parse(xml.as_bytes(), &mut stream).unwrap()
    }

    /// A KeePass-shaped document with the constructs this model does not
    /// preserve: entry history, an entry attachment, custom data, and
    /// deleted objects.
    const LOSSY_XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><Generator>KeePass</Generator>
<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>
</Meta><Root>
<Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>
<Entry><UUID>BBBBBBBBBBBBBBBBBBBBBA==</UUID><IconID>1</IconID>
<String><Key>Title</Key><Value>Live Entry</Value></String>
<String><Key>Password</Key><Value Protected="True">AAAA</Value></String>
<History>
  <Entry><UUID>CCCCCCCCCCCCCCCCCCCCCA==</UUID><String><Key>Title</Key><Value>Old 1</Value></String></Entry>
  <Entry><UUID>DDDDDDDDDDDDDDDDDDDDDDA==</UUID><String><Key>Title</Key><Value>Old 2</Value></String></Entry>
</History>
<Binaries><Binary Ref="0"><Key>f.txt</Key><Value>SGVsbG8=</Value></Binary></Binaries>
</Entry>
</Group>
<DeletedObjects><DeletedObject><UUID>EEEEEEEEEEEEEEEEEEEEEA==</UUID></DeletedObject></DeletedObjects>
</Root></KeePassFile>"#;

    /// Regression: history revisions used to REPLACE the live entry (the
    /// nested `</Entry>` pushed the revision and cleared the current one).
    #[test]
    fn history_does_not_replace_live_entries() {
        let vault = parse_str(LOSSY_XML);
        assert_eq!(vault.root.entries.len(), 1, "only the live entry remains");
        let e = &vault.root.entries[0];
        assert_eq!(e.title(), Some("Live Entry"));
        let pw = e.fields.iter().find(|f| f.key == "Password").unwrap();
        assert!(pw.protected, "live entry keeps its protected field");
    }

    #[test]
    fn lossy_constructs_are_counted() {
        let vault = parse_str(LOSSY_XML);
        assert_eq!(vault.losses.history_entries, 2);
        assert_eq!(vault.losses.binary_refs, 1);
        assert_eq!(vault.losses.custom_data, 1);
        assert_eq!(vault.losses.deleted_objects, 1);
        assert_eq!(vault.losses.protected_binaries, 0); // set by vault::open
        assert!(!vault.losses.is_empty());
        assert!(vault.losses.describe().contains("2 history item(s)"));
    }

    #[test]
    fn own_output_reports_no_losses() {
        let mut vault = Vault::create("t").unwrap();
        let mut e = Entry::default();
        e.set_field("Title", "x", false);
        e.set_field("Password", "secret", true);
        vault.root.entries.push(e);
        vault.root.groups.push(Group {
            uuid: vec![7u8; 16],
            name: "Sub".to_string(),
            ..Default::default()
        });

        let mut enc = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &[7u8; 32]);
        let xml = serialize(&vault, &mut enc, &[0u8; 32]).unwrap();
        // Same key as the serializer, fresh stream at position 0.
        let mut dec = ProtectedStream::new(ProtectedStreamKind::ChaCha20, &[7u8; 32]);
        let parsed = parse(&xml, &mut dec).unwrap();
        assert!(parsed.losses.is_empty(), "{:?}", parsed.losses);
        assert_eq!(parsed.root.entries[0].password(), Some("secret"));
    }
}
