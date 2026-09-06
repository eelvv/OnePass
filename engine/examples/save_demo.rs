//! Demonstrates opening a KDBX file and saving it back.
//!
//! Usage: cargo run --release --example save_demo -- <input> <output> <password>

use onepass_engine::db::{open, save};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("../examples/example1.kdbx");
    let output = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("../examples/output.kdbx");
    let out_password = args.get(3).map(|s| s.as_str()).unwrap_or("example1");

    let data = std::fs::read(input).expect("read input");
    let vault = open(&data, b"example1").expect("open input");
    println!(
        "Opened {input}: database \"{}\", {} top-level group(s)",
        vault.database_name,
        vault.root.groups.len()
    );

    let saved = save(&vault, out_password.as_bytes()).expect("save");
    std::fs::write(output, &saved).expect("write output");
    println!(
        "Saved {} bytes to {output} (password: {out_password})",
        saved.len()
    );
}
