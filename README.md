# OnePass

[![Rust CI](https://github.com/eelvv/OnePass/actions/workflows/ci.yml/badge.svg)](https://github.com/eelvv/OnePass/actions/workflows/ci.yml)

An offline password manager with built-in two-factor authentication (2FA)
code generation. It reads and writes standard KeePass `.kdbx` vaults, so your
passwords stay compatible with the wider KeePass ecosystem.

## Features

- KeePass KDBX 4 vaults (Argon2 / AES-KDF, AES / Twofish / ChaCha20)
- 2FA codes: TOTP, HOTP, plus Steam, MOTP and Yandex variants, with a live countdown
- Import / export of 2FA entries (Aegis JSON, `otpauth://` lists, Google Authenticator migration)
- Interactive terminal UI (`onepass-cli`): browse, edit, multi-select, copy to clipboard

## Documentation

| Component | Description | Docs |
|---|---|---|
| `onepass-engine` | Core library: vault format, crypto, OTP, import/export | [`engine/README.md`](engine/README.md) |
| `onepass-cli` | Interactive terminal UI | [`cli/README.md`](cli/README.md) |

## Quick start

```bash
cargo build --release
cargo run --release --example create_demo     # build a demo vault (password: example1)
./target/release/onepass-cli examples/output.kdbx
```

Non-interactive use (scripts / CI) passes the master password through the
`ONEPASS_PASSWORD` environment variable:

```bash
ONEPASS_PASSWORD=example1 ./target/release/onepass-cli examples/output.kdbx
```

## Development

```bash
cargo test --release      # reference vectors + real-file interop + round-trip
cargo clippy --workspace
cargo fmt --all
```

## Releases & versioning

Each component carries its own semver (`onepass-cli` 0.1.3, `onepass-engine`
0.1.1) and is released independently through component tags:

| Tag | Builds | Example |
|---|---|---|
| `cli-v*` | CLI binaries only | `cli-v0.1.3` |
| `app-v*` / `desktop-v*` | future components | — |
| `v*` | global bundle: every component in one release | `v0.2.0` |

Release together by pushing several tags at once:

```bash
git tag cli-v0.1.3 app-v0.1.0
git push origin cli-v0.1.3 app-v0.1.0
```

`onepass-engine` is a library and is never tagged on its own; the engine
version bundled in a binary is noted in that release's notes. Binaries for
Linux (x86_64), macOS (aarch64) and Windows (x86_64) are attached to every
CLI/bundle release automatically.

## Acknowledgements

Standards and formats this project is based on, and the open-source projects
consulted for behavioural reference (no code is copied):

- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — KDBX 4 file format
- [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) — 2FA import/export formats
