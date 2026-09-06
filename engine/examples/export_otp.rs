//! Exports all OTP entries from a KDBX file.
//!
//! Usage:
//!   cargo run --release --example export_otp -- <input.kdbx> <password> <outdir>
//!
//! Produces:
//!   <outdir>/otpauth-uris.txt   (one otpauth:// URI per line)
//!   <outdir>/aegis.json         (Aegis plaintext vault)
//!   <outdir>/google-migration.txt (Google Authenticator migration URI)

use onepass_engine::db::{open, otp_entries, export_aegis_json, export_google_migration, export_otpauth_uris};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = args.get(1).map(|s| s.as_str()).unwrap_or("../examples/output.kdbx");
    let password = args.get(2).map(|s| s.as_str()).unwrap_or("example1");
    let outdir = args.get(3).map(|s| s.as_str()).unwrap_or("../examples");

    let data = std::fs::read(input).expect("read input");
    let vault = open(&data, password.as_bytes()).expect("open vault");
    let entries = otp_entries(&vault);
    println!("Found {} OTP entries", entries.len());

    let uris = export_otpauth_uris(&entries).expect("export uris");
    std::fs::write(format!("{outdir}/otpauth-uris.txt"), &uris).expect("write uris");
    println!("Wrote {outdir}/otpauth-uris.txt");

    let aegis = export_aegis_json(&entries).expect("export aegis");
    std::fs::write(format!("{outdir}/aegis.json"), &aegis).expect("write aegis");
    println!("Wrote {outdir}/aegis.json");

    let migration = export_google_migration(&entries).expect("export migration");
    std::fs::write(format!("{outdir}/google-migration.txt"), &migration).expect("write migration");
    println!("Wrote {outdir}/google-migration.txt");
}
