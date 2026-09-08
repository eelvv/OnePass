# OnePass Android App

Flutter client for OnePass. The UI is Flutter; **all engine logic and all
plaintext vault data live in Rust** — Dart only ever receives DTO copies
across the FFI boundary (see [Architecture](#architecture)).

## Features

- Unlock / create KeePass `.kdbx` vaults (stored in the app-private
  documents directory)
- Entry list with live search, multi-select delete
- Unified add/edit form for password and 2FA entries (same fields as the
  CLI), built-in password generator with policy options
- Entry detail: protected fields revealed on demand (15 s auto-hide),
  copy with clipboard auto-clear (60 s), live OTP code with countdown
- Import: Aegis JSON, `otpauth://` URI lists, Google Authenticator
  migration (auto-detected), whole `.kdbx` vault files
- Export: 2FA as `otpauth://` URIs or Aegis JSON (system share sheet),
  `.kdbx` vault copy
- Appearance: light/dark/system theme, accent color presets
- Language: 中文 / English / follow system
- Security: lock on background (drops the Rust session, password zeroized),
  master password change
- Diagnostics: append-only file log, shareable from Settings

## Architecture

```
lib/features/*            UI (lock, vault list, entry detail/edit, settings)
lib/state/                Riverpod controllers (settings, session, entries)
lib/shared/               logger, friendly error mapping, UI helpers
lib/theme/                Material 3 theme from seed color
lib/l10n/                 generated localizations (app_en / app_zh)
lib/src/rust/             GENERATED Dart bindings - committed, do not edit
rust/ (rust_lib_onepass)  bridge crate: session + API over onepass-engine
rust_builder/             cargokit gradle plugin (compiles Rust in CI builds)
android/                  Android host project (compileSdk pinned to 36)
```

Data flow: `Dart UI → generated FFI stub → C ABI → rust/src/frb_generated.rs
→ rust/src/logic.rs → onepass-engine`. The decrypted vault and the master
password live only inside `rust/src/session.rs` behind a Mutex; locking the
app drops the session and zeroizes the password. Bindings are committed and
verified against regeneration by a CI drift guard.

## Development

Prerequisites: Flutter stable, Rust with the `aarch64-linux-android` target
(only needed when building locally), Android SDK/NDK.

```bash
cd app
flutter pub get                 # also regenerates l10n (generate: true)
flutter analyze                 # must be clean
flutter test                    # pure-Dart unit tests
flutter test integration_test  # device/emulator FFI smoke test (needs device)
```

After changing any Rust API in `rust/src/api/`:

```bash
flutter_rust_bridge_codegen generate   # version must match the crate pin
```

Generated files (`rust/src/frb_generated.rs`, `lib/src/rust/**`) are
committed; CI regenerates and fails on drift. L10n sources live in
`lib/l10n/*.arb` with generated Dart committed as well.

There is intentionally no local Android build step in the dev loop — APKs
are built by GitHub CI:

```bash
git tag app-v0.1.2 && git push origin app-v0.1.2   # release + APK asset
```

Branch pushes (main, flutter-app) produce a per-run artifact
`onepass-app-android-arm64.apk` for manual testing.

## Logging

The app writes `<app support>/logs/onepass.log` (rotated at 1 MB). Settings
→ Logs shows the path and offers share/clear. Passwords, entry secrets and
OTP codes are never logged.
