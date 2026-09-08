# OnePass Engine

Core library behind OnePass. Handles reading and writing KeePass KDBX 4
vaults, computing OTP codes (TOTP, HOTP, Steam, MOTP, Yandex), parsing and
building `otpauth://` / `motp://` URIs, and importing/exporting 2FA entries
(Aegis JSON, URI lists, Google Authenticator migration).

Only public standards and documented algorithms are implemented — no GPL
code is included.

## Modules

| Path | Purpose |
|---|---|
| `cipher/` | AES-256-CBC, Twofish-256-CBC, ChaCha20 |
| `kdf/` | Argon2 (d/i/id) and AES-KDF key derivation |
| `db/` | KDBX 4 header, inner header, content streams, XML model, vault I/O, OTP integration |
| `otp/` | HOTP, TOTP, Steam, MOTP, Yandex.Key |
| `uri/` | `otpauth://` and `motp://` parse/build |
| `encoding/` | Base32 (RFC 4648), Hex |

## Validation

- RFC 4226 Appendix D (HOTP)
- RFC 6238 Appendix B (TOTP SHA-1/256/512)
- RFC 4648 Section 10 (Base32)
- Real `.kdbx` round-trip (open → save → re-open)

## Build / Test

```bash
cargo test --release
```
