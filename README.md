# OnePass

A password manager + 2FA (TOTP/HOTP) cross-platform solution built from scratch in Rust.

- **`engine/`** — Rust core: KeePass KDBX 4 read/write (Argon2/AES-KDF, AES/Twofish/ChaCha20, HMAC blocks, inner random stream, gzip, XML), OTP algorithms (RFC 4226/6238 + Steam/MOTP/Yandex), `otpauth://` URI parsing and construction, 2FA import/export (Aegis JSON, URI list, Google Authenticator protobuf migration). Functionally referenced from KeePassDX and Aegis; independent implementation (no copied GPL code).
- **`cli/`** — `onepass-cli`: full-screen interactive TUI manager (ratatui). See [`cli/README.md`](cli/README.md) for keybindings, multi-select, copy-to-clipboard (`u`/`p`/`U`/`o`/`c`/`v`), in-place edit (`Enter` in Details), 2FA refresh (`F5`), help (`?`), master-password change (`P`), and centered popup design.
- **`reference/`** — Functionally referenced upstream open-source projects (KeePassDX, Aegis) kept for reference; excluded from build (`.gitignore`).

## Build

```bash
cargo build --release
```

Workspace `Cargo.lock` is the only lock file; member-level `Cargo.lock` files are removed.

## Usage (CLI)

```bash
# Generate the demo vault first (required for the examples below):
cargo run --release --example create_demo

# Open the demo vault:
./target/release/onepass-cli examples/output.kdbx    # password: example1
# Non-interactive (script/CI): pass via environment:
ONEPASS_PASSWORD=example1 ./target/release/onepass-cli examples/output.kdbx
```

## Tests

```bash
cargo test --release
```

Includes RFC reference vectors, real `.kdbx` interop, and end-to-end round-trip tests.

## References

This project is functionally referenced from the following open-source projects but contains no copied GPL code:

- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — KDBX 4 format reference and de-facto algorithms
- [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) — Aegis JSON / `otpauth://` format reference
- [rust-argon2](https://github.com/sru-systems/rust-argon2) / [RustCrypto formats](https://github.com/RustCrypto/formats) — for Argon2 and cipher reference vectors (independent implementations)
