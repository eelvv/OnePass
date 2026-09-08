//! OnePass CLI — interactive TUI password manager and 2FA console.
//!
//! Usage:
//!   onepass-cli [vault.kdbx]
//!
//! Opens (or creates) a KeePass-compatible `.kdbx` vault and provides a
//! full-screen terminal UI for browsing, editing, 2FA codes with a live
//! countdown, and import/export.

mod app;
mod clipboard;
mod ui;

use std::path::Path;
use std::process;

use crossterm::event::{self, Event, KeyEventKind};
use onepass_engine::db::{open, random_bytes, save, Group, Vault};
use ratatui::crossterm;
use ratatui::DefaultTerminal;
use rpassword::prompt_password;

use crate::app::App;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().skip(1).any(|a| a == "-h" || a == "--help") {
        print_usage();
        return;
    }
    if args.iter().skip(1).any(|a| a == "-V" || a == "--version") {
        println!("onepass-cli {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let file = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "passwords.kdbx".to_string());

    let app = match open_or_create(&file) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let mut terminal = match ratatui::try_init() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "error: failed to initialize terminal: {e}\n(OnePass CLI needs an interactive terminal)"
            );
            process::exit(1);
        }
    };
    let result = run_app(&mut terminal, app);
    ratatui::restore();

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn open_or_create(file: &str) -> Result<App, String> {
    // ONEPASS_PASSWORD env var enables non-interactive use (CI/scripting).
    let env_password = std::env::var("ONEPASS_PASSWORD").ok();

    if Path::new(file).exists() {
        let data = fs_err(file)?;
        let mut last_err = String::new();
        for attempt in 1..=3 {
            let password = match &env_password {
                Some(p) => p.clone(),
                None => prompt_password("Password: ").map_err(|e| e.to_string())?,
            };
            match open(&data, password.as_bytes()) {
                Ok(vault) => {
                    return Ok(App::new(vault, password, file.to_string()));
                }
                Err(e) => {
                    last_err = e.to_string();
                    if env_password.is_some() {
                        return Err(format!("could not open {file}: {last_err}"));
                    }
                    eprintln!("Wrong password ({attempt}/3): {last_err}");
                }
            }
        }
        Err(format!("could not open {file}: {last_err}"))
    } else {
        println!("No vault at '{file}' — creating a new one.");
        let password = match &env_password {
            Some(p) => p.clone(),
            None => {
                let pw = prompt_password("New master password: ").map_err(|e| e.to_string())?;
                let confirm = prompt_password("Confirm: ").map_err(|e| e.to_string())?;
                if pw != confirm {
                    return Err("passwords do not match".to_string());
                }
                pw
            }
        };
        if password.is_empty() {
            return Err("master password must not be empty".to_string());
        }
        let name = Path::new(file)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "My Passwords".to_string());
        let vault = Vault {
            database_name: name,
            root: Group {
                uuid: random_bytes(16).map_err(|e| e.to_string())?,
                name: "Root".to_string(),
                ..Default::default()
            },
        };
        Ok(App::new(vault, password, file.to_string()))
    }
}

fn fs_err(file: &str) -> Result<Vec<u8>, String> {
    std::fs::read(file).map_err(|e| format!("read {file}: {e}"))
}

fn print_usage() {
    println!("onepass-cli — interactive TUI password manager + 2FA console");
    println!();
    println!("Usage: onepass-cli [vault.kdbx]");
    println!();
    println!("Arguments:");
    println!("  vault.kdbx    Vault file to open or create (default: passwords.kdbx)");
    println!();
    println!("Options:");
    println!("  -h, --help     Print this help");
    println!("  -V, --version  Print version");
    println!();
    println!("Environment:");
    println!("  ONEPASS_PASSWORD  Master password (non-interactive use)");
}

fn run_app(terminal: &mut DefaultTerminal, mut app: App) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        // 200ms poll keeps the OTP countdown live without busy-waiting.
        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }
        if app.quit {
            break;
        }
    }

    // Persist automatically on clean exit if there are unsaved changes and
    // the user did not choose to discard them.
    if app.dirty && !app.discard_on_quit {
        match save(&app.vault, app.password.as_bytes()) {
            Ok(bytes) => {
                std::fs::write(&app.file, bytes)?;
                eprintln!("Unsaved changes were saved to {}", app.file);
            }
            Err(e) => eprintln!("warning: auto-save failed: {e}"),
        }
    }
    Ok(())
}
