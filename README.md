# OnePass

[![Rust CI](https://github.com/eelvv/OnePass/actions/workflows/ci.yml/badge.svg)](https://github.com/eelvv/OnePass/actions/workflows/ci.yml)
[![App build](https://github.com/eelvv/OnePass/actions/workflows/app.yml/badge.svg)](https://github.com/eelvv/OnePass/actions/workflows/app.yml)

An offline password manager with built-in two-factor authentication (2FA)
code generation. It reads and writes standard KeePass `.kdbx` vaults, so your
passwords stay compatible with the wider KeePass ecosystem.

## Features

- KeePass KDBX 4 vaults (Argon2 / AES-KDF, AES / Twofish / ChaCha20)
- 2FA codes: TOTP, HOTP, plus Steam, MOTP and Yandex variants, with a live countdown
- Import / export of 2FA entries (Aegis JSON, `otpauth://` lists, Google Authenticator migration)
- Interactive terminal UI (`onepass-cli`): browse, edit, multi-select, copy to clipboard
- Android app (`onepass-app`): Flutter UI over the Rust engine — vault
  management, 2FA codes with live countdown, kdbx/2FA import & export,
  biometric-friendly lock flow, zh/en i18n

## Documentation

| Component | Description | Docs |
|---|---|---|
| `onepass-engine` | Core library: vault format, crypto, OTP, import/export | [`engine/README.md`](engine/README.md) |
| `onepass-cli` | Interactive terminal UI | [`cli/README.md`](cli/README.md) |
| `onepass-app` | Android client (Flutter UI + Rust core via FFI) | [`app/README.md`](app/README.md) |

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

### Android app

Install the latest APK from the
[app releases](https://github.com/eelvv/OnePass/releases) — every `app-v*`
tag publishes `onepass-app-android-arm64.apk` automatically. See
[`app/README.md`](app/README.md) for architecture and development.

## Development

```bash
cargo test --release      # reference vectors + real-file interop + round-trip
cargo clippy --workspace
cargo fmt --all
```

## Releases & downloads

Each component is versioned and released independently through component
tags:

| Tag | Builds |
|---|---|
| `cli-v*` | CLI binaries (`onepass-cli-<platform>.tar.gz`) |
| `app-v*` | Android app (`onepass-app-android-arm64.apk`) |
| `v*` | global bundle: every component in one release |

| Component | Latest release | Downloads |
|---|---|---|
| CLI | [![CLI](https://img.shields.io/github/v/release/eelvv/OnePass?filter=cli-v*&label=%20)](https://github.com/eelvv/OnePass/releases?q=cli-v) | [Linux / macOS / Windows](https://github.com/eelvv/OnePass/releases?q=cli-v) |
| Android app | [![App](https://img.shields.io/github/v/release/eelvv/OnePass?filter=app-v*&label=%20)](https://github.com/eelvv/OnePass/releases?q=app-v) | [APK (arm64)](https://github.com/eelvv/OnePass/releases?q=app-v) |

`onepass-engine` is a library and is never tagged on its own; the engine
version bundled in a binary is noted in that release's notes.

## Acknowledgements

Standards and formats this project is based on, and the open-source projects
consulted for behavioural reference (no code is copied):

- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — KDBX 4 file format
- [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) — 2FA import/export formats
