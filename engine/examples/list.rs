//! Lists all entries in a KDBX file (for verification).

use onepass_engine::db::{open, Group};

fn walk(g: &Group, depth: usize, out: &mut Vec<String>) {
    for e in &g.entries {
        out.push(format!(
            "{}{} | {} | {} | {} | {}",
            "  ".repeat(depth),
            e.title().unwrap_or(""),
            e.username().unwrap_or(""),
            e.password().unwrap_or(""),
            e.url().unwrap_or(""),
            g.name
        ));
    }
    for sg in &g.groups {
        walk(sg, depth + 1, out);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = args.get(1).map(|s| s.as_str()).unwrap_or("../examples/output.kdbx");
    let password = args.get(2).map(|s| s.as_str()).unwrap_or("example1");

    let data = std::fs::read(input).expect("read");
    let vault = open(&data, password.as_bytes()).expect("open");
    println!("database: {}", vault.database_name);
    let mut lines = Vec::new();
    walk(&vault.root, 0, &mut lines);
    for l in lines {
        println!("{l}");
    }
}
