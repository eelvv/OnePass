# OnePass Engine

Independent Rust core for KeePass KDBX 4 I/O, OTP algorithms (RFC 4226/6238,
Steam, MOTP, Yandex.Key), `otpauth://` URI parsing/construction, and 2FA
import/export (Aegis JSON / URI list / Google Authenticator migration).

Only public standards and publicly documented algorithms are implemented;
no GPL code is included.

## Validation

- RFC 4226 Appendix D (HOTP reference vectors)
- RFC 6238 Appendix B (TOTP reference vectors)
- RFC 4648 Section 10 (Base32)
- Steam / MOTP / Yandex verified against independent Python reference
  implementations

## Build / Test

```bash
cargo test --release
```


