# OnePass

Password manager + 2FA (TOTP/HOTP) built as an independent Rust core
(`onepass-engine`) and an interactive terminal interface (`onepass-cli`).

## Project structure

| Path | Role | Docs |
|---|---|---|
| [`engine/`](engine/) | Core library (KDBX 4, OTP, URI, import/export) | [`engine/README.md`](engine/README.md) |
| [`cli/`](cli/) | TUI manager (`onepass-cli`) | [`cli/README.md`](cli/README.md) |
| [`reference/`](reference/) | Upstream references (KeePassDX, Aegis); excluded from build (`.gitignore`) | — |

## Quick start

```bash
cargo build --release
./target/release/onepass-cli [vault.kdbx]
# Generate the demo vault first (see cli/README.md for details):
cargo run --release --example create_demo
```

## CI

[![Rust CI](https://github.com/eelvv/OnePass/actions/workflows/ci.yml/badge.svg)](https://github.com/eelvv/OnePass/actions/workflows/ci.yml)

- `cargo fmt --all -- --check`
- `cargo test --release`
- `cargo clippy --workspace -D warnings`
- Cross-platform release builds for Linux (x86_64), macOS (aarch64), Windows (x86_64) triggered on tags (`v*`, `cli-v*`).

## References

Only public standards and documented algorithms are implemented; no GPL code is copied.

- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — KDBX 4 format reference
- [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) — Aegis JSON / `otpauth://` format reference
- [RustCrypto formats](https://github.com/RustCrypto/formats) — cipher / encoding reference implementations (independent)

