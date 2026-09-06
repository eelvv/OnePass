# OnePass Engine (Rust core)

OnePass 的核心引擎：独立实现的密码学与格式逻辑（功能参考 KeePassDX / Aegis，
不复制 GPL 代码，仅按公开标准 RFC 4226/6238、Google Key URI 格式与公开记录的
de-facto 算法 Steam/MOTP/Yandex.Key 重写）。

## 模块

- `encoding/` — Base32 (RFC 4648)、Hex
- `otp/` — HOTP (RFC 4226)、TOTP (RFC 6238)、Steam、MOTP、Yandex.Key
- `uri/` — `otpauth://` / `motp://` 解析与构建（KeePassDX 兼容输出）

## 正确性验证

- RFC 4226 附录 D（HOTP）
- RFC 6238 附录 B（TOTP SHA1/SHA256/SHA512）
- RFC 4648 §10（Base32）
- Steam/MOTP/Yandex 由独立 Python 实现生成的已知答案向量

## 构建与测试

```bash
# 若全局 cargo 镜像不可用，本目录 .cargo/config.toml 已覆盖为 rsproxy
cargo test
```

> 说明：`engine/.cargo/config.toml` 将全局 `mirror` 源重定向到 rsproxy.cn，
> 以绕过当前返回 403 的 cernet 镜像；不改动用户全局配置。

## 待实现

- `kdf/` — Argon2、AES-KDF（KeePass 主密钥派生）
- `cipher/` — AES / Twofish / ChaCha20
- `kdbx/` — KDBX v1–v4 解析与输出
