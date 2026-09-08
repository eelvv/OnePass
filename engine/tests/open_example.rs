//! End-to-end test: open a real KeePass `.kdbx` file with `db::open`.

use onepass_engine::db::{open, Group};

fn collect_entries<'a>(g: &'a Group, out: &mut Vec<&'a onepass_engine::db::Entry>) {
    for e in &g.entries {
        out.push(e);
    }
    for sg in &g.groups {
        collect_entries(sg, out);
    }
}

#[test]
fn open_example() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/example1.kdbx");
    let data = std::fs::read(path).expect("example file not found");

    let vault = open(&data, b"example1").expect("open vault");

    let mut entries = Vec::new();
    collect_entries(&vault.root, &mut entries);

    assert_eq!(entries.len(), 2, "expected two entries");
    for e in &entries {
        assert_eq!(e.title(), Some("example1"));
        assert_eq!(e.username(), Some("example1"));
        assert_eq!(e.password(), Some("example1"));
        assert_eq!(e.url(), Some("https://example1.com"));
    }
}

#[test]
fn wrong_password_fails() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../examples/example1.kdbx");
    let data = std::fs::read(path).expect("example file not found");
    assert!(matches!(
        onepass_engine::db::open(&data, b"wrong-password"),
        Err(onepass_engine::Error::WrongPassword)
    ));
}
