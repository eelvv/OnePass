# OnePass

密码管理 + 2FA（TOTP/HOTP）一体的跨平台方案。

- **`engine/`** — Rust 核心引擎：KeePass KDBX 4 读写（Argon2/AES-KDF、AES/Twofish/ChaCha20、
  HMAC 块、内部随机流、gzip、XML）、OTP 算法（RFC 4226/6238 + Steam/MOTP/Yandex）、
  `otpauth://` URI、2FA 导入导出（Aegis JSON / URI 列表 / Google Authenticator 迁移）。
  核心逻辑全部独立重写（依赖均为 MIT/Apache），以公开测试向量 +
  真实 KeePass 文件互操作双重复验证。
- **`cli/`** — `onepass-cli`：ratatui 全屏 TUI 密码管理器（浏览/添加/删除/2FA 实时验证码/导入导出）。
- **`reference/`** — 功能参考的上游开源项目（KeePassDX、Aegis，不参与构建，已 gitignore）。

## 构建

```bash
cargo build --release
```

> 本机若全局 cargo 镜像不可用，`.cargo/config.toml` 已将镜像重定向到 rsproxy
> （该文件被 gitignore，属于机器特定配置）。

## 使用 CLI

```bash
# 打开已有库（无则创建）
./target/release/onepass-cli examples/output.kdbx     # 密码: example1

# 非交互（脚本/CI）：环境变量传密码
ONEPASS_PASSWORD=example1 ./target/release/onepass-cli examples/output.kdbx
```

TUI 按键：

| 键 | 作用 |
|---|---|
| `j/k` `↑/↓` | 选择条目 |
| `s` | 保存 |
| `a` | 添加密码条目（表单，密码留空自动生成强密码） |
| `t` | 添加 2FA 条目（粘贴 `otpauth://` URI，即扫码内容） |
| `d` | 删除条目 |
| `/` | 搜索过滤 |
| `r` | 显示/隐藏密码与 OTP secret |
| `i` / `e` | 导入 / 导出 2FA（Aegis JSON、URI 列表） |
| `q` | 退出（有未保存修改会确认；正常退出自动保存） |

## 示例程序（engine）

```bash
cargo run --release --example create_demo   # 生成演示库（examples/output.kdbx）
cargo run --release --example list          # 列出条目
cargo run --release --example export_otp    # 导出 2FA（Aegis JSON / URI / Google 迁移）
cargo run --release --example import_otp    # 导入 2FA（自动识别格式）
```

## 测试

```bash
cargo test --release   # 99 个测试：RFC 向量 + 真实 KDBX 互操作 + 端到端
```
