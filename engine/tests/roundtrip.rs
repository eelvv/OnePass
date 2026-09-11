//! Round-trip test: open a real `.kdbx`, save it back, and re-open.

use onepass_engine::db::{open, save, Group};

fn collect<'a>(g: &'a Group, out: &mut Vec<&'a onepass_engine::db::Entry>) {
    for e in &g.entries {
        out.push(e);
    }
    for sg in &g.groups {
        collect(sg, out);
    }
}

fn entries(vault: &onepass_engine::db::Vault) -> Vec<(String, String, String, String)> {
    let mut es = Vec::new();
    collect(&vault.root, &mut es);
    es.into_iter()
        .map(|e| {
            (
                e.title().unwrap_or("").to_string(),
                e.username().unwrap_or("").to_string(),
                e.password().unwrap_or("").to_string(),
                e.url().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[test]
fn save_roundtrip() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/example1.kdbx");
    let data = std::fs::read(path).expect("example file not found");

    let vault = open(&data, b"example1").expect("open");
    let original = entries(&vault);

    // Save with a different password.
    let saved = save(&vault, b"example2").expect("save");
    assert!(!saved.is_empty());

    // Re-open the saved bytes.
    let reopened = open(&saved, b"example2").expect("re-open saved");
    assert_eq!(entries(&reopened), original);

    // Wrong password must fail on the saved file too.
    assert!(open(&saved, b"wrong").is_err());
}

#[test]
fn attachments_survive_save_open() {
    use onepass_engine::db::{random_bytes, InnerBinary, Vault};

    let vault = Vault {
        database_name: "attachments".to_string(),
        root: Group {
            uuid: random_bytes(16).unwrap(),
            name: "Root".to_string(),
            ..Default::default()
        },
        binaries: vec![InnerBinary {
            protected: false,
            data: b"hello attachment".to_vec(),
        }],
        ..Default::default()
    };

    let saved = save(&vault, b"pw").unwrap();
    let opened = open(&saved, b"pw").unwrap();

    assert_eq!(opened.binaries.len(), 1, "attachment blob must survive");
    assert_eq!(opened.binaries[0].data, b"hello attachment".to_vec());
    assert!(!opened.binaries[0].protected);
    assert!(opened.losses.is_empty());
}
