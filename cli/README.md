# onepass-cli

Interactive TUI password manager + 2FA console over the OnePass engine.

## Usage

```bash
cargo build --release --bin onepass-cli
./target/release/onepass-cli [vault.kdbx]
```

The CLI opens (or creates) a `.kdbx` vault and provides a full-screen terminal UI: entry browsing, editing, 2FA codes with a live countdown, multi-select, copy-to-clipboard (`u`/`p`/`U`/`o`/`c`/`v`), import/export, and master-password change (`P`).

## Keybindings (Normal mode, List focus)

- `j` / `k` / `↑` / `↓` — navigate entries
- `g` / `G` — jump to first / last entry
- `Space` — toggle multi-select on current entry
- `a` — add entry (Password / 2FA unified form)
- `d` — delete selected / delete all marked entries
- `/` — live filter search
- `i` — import 2FA (Aegis JSON / URI list / Google migration)
- `e` — export 2FA (Aegis JSON / URI list / marked entries)
- `Tab` — switch focus between List and Details panels
- `F5` — refresh OTP countdown / reveal timer
- `?` — open help popup
- `q` / `Ctrl+c` — quit (confirm if unsaved changes)
- `s` — save vault
- `P` — change master password (apply immediately; `s` to write to disk)
- `r` — reveal/hide protected fields (auto-hide after 15s)
- `Enter` — edit selected entry (in Details, opens inline edit mode)

## Keybindings (Details focus)

- `j` / `k` — navigate fields
- `c` — copy current field value to clipboard
- `v` — paste clipboard content into current field
- `Enter` — edit selected field (inline, `Char`/`Backspace`/`Enter`/`Esc`)
- `r` — reveal/hide protected field
- `Tab` — switch back to List focus

## Keybindings (Search / InputPath / Confirm / ChangePassword / Help)

- Search (`/`): real-time filter; `Enter` / `Esc` close
- InputPath (`i`/`e`): `Enter` submit; `Esc` cancel
- Confirm (`y`/`n`/`Esc`): confirm/cancel delete or quit
- ChangePassword (`P`): `Enter` applies; `Esc` cancels
- Help (`?`): `j`/`k` scroll; `Esc`/`Enter`/`?` close

## Features

- Multi-select (`Space`) with marked count shown in header (`[x3]`)
- Details panel shows full entry fields + live OTP countdown
- In-place inline edit (`Enter` in Details) without a full popup
- Search, import, export, add/edit, confirm, and help all use centered 3-line popups (`Length(3)` height, centered in middle of screen)
- No emoji icons; pure English labels; readable footer spacing
