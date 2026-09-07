# OnePass

密码管理 + 2FA（TOTP/HOTP）一体的跨平台方案。

[![Rust CI](https://github.com/eelvv/OnePass/actions/workflows/ci.yml/badge.svg)](https://github.com/eelvv/OnePass/actions/workflows/ci.yml)

- **`engine/`** — Rust 核心引擎：KeePass KDBX 4 读写（Argon2/AES-KDF、AES/Twofish/ChaCha20、
  HMAC 块、内部随机流、gzip、XML）、OTP 算法（RFC 4226/6238 + Steam/MOTP/Yandex）、
  `otpauth://` URI、2FA importexport（Aegis JSON / URI 列表 / Google Authenticator 迁移）。
  核心逻辑全部独立重写（依赖均为 MIT/Apache），以公开测试向量 +
  真实 KeePass 文件互操作双重复验证。
- **`cli/`** — `onepass-cli`：ratatui 全屏 TUI 密码管理器（浏览/add加/delete除/2FA 实时验证码/importexport）。
- **`reference/`** — 功能参考的上游开源项目（KeePassDX、Aegis，不参与构建，已 gitignore）。

## 构建

```bash
cargo build --release
```

> 本机若全局 cargo 镜像不可用，`.cargo/config.toml` 已将镜像重定向到 rsproxy
> （该文件被 gitignore，属于机器特定配置）。

## 使用 CLI

```bash
# 打开演示库（首次使用需先生成演示库，见「示例程序」）
./target/release/onepass-cli examples/output.kdbx     # 密码: example1

# 非交互（脚本/CI）：环境变量传密码
ONEPASS_PASSWORD=example1 ./target/release/onepass-cli examples/output.kdbx
```

TUI 按键：

| 键 | 作用 |
|---|---|
| `j/k` `↑/↓` | 选择条目 |
| `s` | save |
| `a` | add加密码条目（表单，密码留空自动生成强密码） |
| `t` | add加 2FA 条目（paste `otpauth://` URI，即扫码内容） |
| `d` | delete除条目 |
| `/` | search过滤 |
| `r` | reveal/hide密码与 OTP secret |
| `i` / `e` | import / export 2FA（Aegis JSON、URI 列表） |
| `q` | quit (unsaved changes will confirm; clean exit auto-saves) |

## 示例程序（engine）

```bash
# 生成演示库（examples/output.kdbx），首次使用前必须执行
cargo run --release --example create_demo

cargo run --release --example list           # 列出条目
cargo run --release --example export_otp     # export 2FA（Aegis JSON / URI / Google 迁移）
cargo run --release --example import_otp     # import 2FA（自动识别格式）
```

## 测试

```bash
cargo test --release   # 99 个测试：RFC 向量 + 真实 KDBX 互操作 + 端到端
```

## 仓库约定

- `.kdbx` 文件仅在 `examples/` 作为测试 fixture（仅 `example1.kdbx`），其余
  `output.kdbx`、`imported.kdbx` 为示例程序生成产物，不提交 git。
- 工作区根目录的 `Cargo.lock` 是唯一的锁文件；各成员子目录的锁文件均已移除。
- `reference/` 存放上游源码仅作阅读，整个目录被 `.gitignore`。
