//! TUI rendering.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use crate::app::{
    now_secs, seconds_remaining, AddForm, AddFormKind, App, ConfirmAction, Mode, Panel, PathAction,
};
use onepass_engine::db::entry_otp;

const HEADER_HEIGHT: u16 = 1;
const FOOTER_HEIGHT: u16 = 1;
const MIN_BODY: u16 = 8;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(HEADER_HEIGHT),
        Constraint::Min(MIN_BODY),
        Constraint::Length(FOOTER_HEIGHT),
    ])
    .areas(area);

    draw_header(f, app, header);

    // Body: list on the left, details on the right.
    let [list_area, details_area] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(body);
    draw_list(f, app, list_area);
    draw_details(f, app, details_area);

    draw_footer(f, app, footer);

    // Modal popups.
    match app.mode {
        Mode::Search => search_popup(f, app),
        Mode::InputPath => input_path_popup(f, app),
        Mode::AddEntry => form_popup(f, app),
        Mode::Confirm => confirm_popup(f, app),
        Mode::ChangePassword => change_password_popup(f, app),
        Mode::Help => help_popup(f, app),
        Mode::Normal => {}
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " *" } else { "" };
    let marked = if app.marked.is_empty() {
        String::new()
    } else {
        format!("  ☑{}", app.marked.len())
    };
    let filter = if app.filter.is_empty() {
        String::new()
    } else {
        format!("  filter: {}", app.filter)
    };
    let panel = match app.panel {
        Panel::List => "[List]",
        Panel::Details => "[Details]",
    };
    let line = Line::from(vec![
        Span::styled(
            " OnePass ",
            Style::new()
                .bold()
                .bg(ratatui::style::Color::Cyan)
                .fg(ratatui::style::Color::Black),
        ),
        Span::raw(format!(
            " {panel} {}{} — {} entries{}{} ",
            app.file,
            dirty,
            count_entries(&app.vault.root),
            marked,
            filter,
        )),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let list = app.filtered_entries();
    let rows: Vec<Row> = list
        .iter()
        .enumerate()
        .map(|(i, (path, e))| {
            let mark = if app.marked.contains(&e.uuid) {
                "☑"
            } else {
                " "
            };
            let kind = if entry_otp(e).is_some() {
                "🔑"
            } else {
                "🔒"
            };
            Row::new(vec![
                Cell::from(format!("{}{}", mark, i + 1)),
                Cell::from(kind),
                Cell::from(path.clone()),
                Cell::from(e.title().unwrap_or("").to_string()),
                Cell::from(e.username().unwrap_or("").to_string()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Length(16),
        Constraint::Min(12),
        Constraint::Min(14),
    ];
    let title = if app.mode == Mode::Search {
        format!(" Entries — search: {}█ ", app.input)
    } else if !app.filter.is_empty() {
        format!(" Entries — filter: {} ", app.filter)
    } else {
        " Entries ".to_string()
    };
    let panel_focused = app.panel == Panel::List;
    let mut table = Table::new(rows, widths)
        .header(
            Row::new(vec!["    #", " ", "Group", "Title", "UserName"])
                .style(Style::new().bold().underlined()),
        )
        .block(
            Block::new()
                .borders(Borders::ALL)
                .border_style(if panel_focused {
                    Style::new().fg(ratatui::style::Color::Cyan)
                } else {
                    Style::default()
                })
                .title(title),
        )
        .row_highlight_style(
            Style::new()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .column_spacing(1);
    if !panel_focused {
        table = table.row_highlight_style(Style::new());
    }
    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_details(f: &mut Frame, app: &mut App, area: Rect) {
    let panel_focused = app.panel == Panel::Details;
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(if panel_focused {
            Style::new().fg(ratatui::style::Color::Cyan)
        } else {
            Style::default()
        })
        .title(Span::styled(" Details ", Style::new().bold()));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(entry) = app.selected_entry() else {
        let empty = Paragraph::new("No entry selected. Press 'a' to add, 't' for 2FA.")
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(empty, inner);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    let mut row_index: usize = 0;

    // Title row.
    let title_line = Line::from(Span::styled(
        entry.title().unwrap_or("(no title)").to_string(),
        Style::new().bold().fg(ratatui::style::Color::Yellow),
    ));
    lines.push(title_line);
    row_index += 1;

    for field in &entry.fields {
        let shown = if field.protected && !app.reveal {
            "•".repeat(field.value.len().min(24))
        } else {
            field.value.clone()
        };
        let value_style = if field.protected && !app.reveal {
            Style::new().fg(ratatui::style::Color::DarkGray)
        } else if field.protected {
            Style::new().fg(ratatui::style::Color::LightRed).bold()
        } else {
            Style::new()
        };
        let mut spans: Vec<Span> = Vec::new();
        if panel_focused && row_index == app.detail_field {
            spans.push(Span::styled(
                " ▸ ",
                Style::new().fg(ratatui::style::Color::Cyan),
            ));
        }
        spans.push(Span::styled(
            format!("{:>9}: ", field.key),
            Style::new().bold(),
        ));
        spans.push(Span::styled(shown, value_style));
        lines.push(Line::from(spans));
        row_index += 1;
    }

    if let Some(p) = entry_otp(entry) {
        if let Ok(code) = p.generate(now_secs()) {
            let label = match p.kind {
                onepass_engine::otp::OtpKind::Hotp => format!("HOTP c={}", p.counter),
                onepass_engine::otp::OtpKind::Steam => "Steam".to_string(),
                _ => format!("TOTP {}s", seconds_remaining(p.period)),
            };
            let mut spans: Vec<Span> = Vec::new();
            if panel_focused && row_index == app.detail_field {
                spans.push(Span::styled(
                    " ▸ ",
                    Style::new().fg(ratatui::style::Color::Cyan),
                ));
            }
            spans.push(Span::styled("  OTP: ", Style::new().bold()));
            spans.push(Span::styled(
                code,
                Style::new()
                    .fg(ratatui::style::Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!("  ({label})")));
            lines.push(Line::from(spans));
        }
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let msg = app.message.clone().unwrap_or_default();
    let panel_hint = match app.panel {
        Panel::List => " List: Space多选 / a添 / t添2FA / d删 / Tab切Details ",
        Panel::Details => " Details: j/k导航 / c复制 / v粘贴 / Enter编辑 / Tab切List ",
    };
    let common = " s 保存 │ / 搜索 │ i 导入 │ e 导出 │ r 显示/隐藏 │ ? 帮助 │ q 退出 ";
    let text = format!("{panel_hint}{common}");
    let line = if msg.is_empty() {
        Line::from(Span::styled(text, Style::new().dim()))
    } else {
        Line::from(Span::styled(
            format!(" {msg} "),
            Style::new()
                .fg(ratatui::style::Color::Black)
                .bg(ratatui::style::Color::Yellow),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn search_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(70, 8, f.area());
    f.render_widget(Clear, area);
    let text = Paragraph::new(format!("{}█  (live filter, Enter/Esc to close)", app.input)).block(
        Block::new()
            .borders(Borders::ALL)
            .title(Span::styled(" Search ", Style::new().bold())),
    );
    f.render_widget(text, area);
}

fn input_path_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(70, 8, f.area());
    f.render_widget(Clear, area);
    let title = match app.input_action {
        Some(PathAction::Import) => "Import — file path (Aegis JSON / URI list / migration URI)",
        _ => "Export — file path (.json = Aegis, other = otpauth URI list)",
    };
    let text = Paragraph::new(format!("{}█", app.input)).block(
        Block::new()
            .borders(Borders::ALL)
            .title(Span::styled(format!(" {title} "), Style::new().bold())),
    );
    f.render_widget(text, area);
}

fn confirm_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 12, f.area());
    f.render_widget(Clear, area);
    let text = match app.confirm {
        Some(ConfirmAction::Quit) => {
            "Unsaved changes — save before quitting?\n\n  [y] save & quit    [n] discard    [Esc] stay"
        }
        Some(ConfirmAction::DeleteMarked) => {
            "Delete the marked entries?\n\n  [y] delete    [n/Esc] cancel"
        }
        _ => "Delete the selected entry?\n\n  [y] delete    [n/Esc] cancel",
    };
    let block = Block::new().borders(Borders::ALL).title(Span::styled(
        " Confirm ",
        Style::new().bold().fg(ratatui::style::Color::Yellow),
    ));
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn change_password_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 14, f.area());
    f.render_widget(Clear, area);
    let masked: String = "•".repeat(app.input.chars().count().min(40));
    let lines = vec![
        Line::from(Span::styled(
            "Set a new master password.",
            Style::new().bold(),
        )),
        Line::from(""),
        Line::from(format!("New: {masked}")),
        Line::from(""),
        Line::from(Span::styled(
            "Enter applies immediately. Press 's' to write to disk.",
            Style::new().dim(),
        )),
    ];
    let block = Block::new().borders(Borders::ALL).title(Span::styled(
        " Change Master Password ",
        Style::new().bold(),
    ));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn help_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(70, 70, f.area());
    f.render_widget(Clear, area);
    let sections: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "Global",
            vec![
                ("Tab", "切换 List / Details 面板"),
                ("?", "打开 / 关闭本帮助"),
                ("s", "保存当前库到磁盘"),
                ("P", "修改 master password（仅内存生效，需 s 写入）"),
                ("q", "退出（未保存会确认）"),
                ("Esc", "清除筛选 / 返回 Normal"),
            ],
        ),
        (
            "List 面板",
            vec![
                ("j/k", "上下移动"),
                ("g/G", "跳到首 / 末"),
                ("Space", "切换当前条目多选"),
                ("a", "添加 密码条目"),
                ("t", "添加 2FA 条目"),
                ("d", "删除当前 / 所有标记条目"),
                ("Enter", "编辑当前条目"),
                ("u / p / U / o", "复制 username / password / URL / OTP code"),
                ("r", "显示/隐藏密码（15s 自动隐藏）"),
            ],
        ),
        (
            "Details 面板",
            vec![
                ("j/k", "在字段之间移动"),
                ("c", "复制当前字段到剪贴板"),
                ("v", "把剪贴板内容写入当前字段"),
                ("Enter", "切换到 List 面板并编辑当前条目"),
                ("r", "显示/隐藏密码"),
            ],
        ),
        (
            "筛选 / 导入 / 导出",
            vec![
                ("/", "进入搜索（实时过滤）"),
                ("i", "导入 2FA（Aegis JSON / URI list / Google 迁移）"),
                ("e", "导出 2FA（无标记→全部；有标记→仅标记）"),
                ("F5", "刷新 OTP 显示"),
            ],
        ),
    ];

    let mut lines: Vec<Line> = Vec::new();
    for (header, rows) in sections {
        lines.push(Line::from(Span::styled(
            format!(" {header} "),
            Style::new()
                .bold()
                .bg(ratatui::style::Color::Cyan)
                .fg(ratatui::style::Color::Black),
        )));
        for (k, v) in rows {
            lines.push(Line::from(vec![
                Span::styled(format!("  {k:<10}"), Style::new().bold()),
                Span::raw(v.to_string()),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        " Press ?/Esc/Enter to close.  j/k scrolls.",
        Style::new().dim(),
    )));

    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(" Help ", Style::new().bold()));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let para = Paragraph::new(lines)
        .scroll((app.help_scroll, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(para, inner);
}

fn form_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(72, 60, f.area());
    f.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    let form = &app.form;
    let editing = if form.editing_uuid.is_some() {
        "Edit"
    } else {
        "Add"
    };
    let _kind_label = match form.kind {
        AddFormKind::Password => "Password",
        AddFormKind::TwoFa => "2FA",
    };
    lines.push(Line::from(Span::styled(
        format!(" {editing} entry "),
        Style::new().bold().fg(ratatui::style::Color::Cyan),
    )));
    lines.push(Line::from(""));

    // Row 0: type selector.
    let selector_left = if form.field == 0 { " ▸ " } else { "   " };
    let type_display = match form.kind {
        AddFormKind::Password => {
            if form.field == 0 {
                "Password ← → 2FA"
            } else {
                "Password"
            }
        }
        AddFormKind::TwoFa => {
            if form.field == 0 {
                "Password ← → 2FA"
            } else {
                "2FA"
            }
        }
    };
    let type_style = if form.field == 0 {
        Style::new()
            .bg(ratatui::style::Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };
    lines.push(Line::from(vec![
        Span::styled(selector_left, type_style),
        Span::styled("Type: ", Style::new().bold()),
        Span::styled(type_display, type_style),
    ]));
    lines.push(Line::from(""));

    // Body rows.
    match form.kind {
        AddFormKind::Password => render_password_fields(&mut lines, form),
        AddFormKind::TwoFa => render_twofa_fields(&mut lines, form),
    }

    lines.push(Line::from(""));
    let hint = match form.kind {
        AddFormKind::Password => "Tab/↑↓ 切换字段 · Enter 提交 · Esc 取消",
        AddFormKind::TwoFa => {
            "Tab/↑↓ 切换字段 · ←→ 在第1行(类型)和OtpKind行切选 · Enter 提交 · Esc 取消"
        }
    };
    lines.push(Line::from(Span::styled(hint, Style::new().dim())));

    let block = Block::new().borders(Borders::ALL).title(Span::styled(
        format!(" {editing} Entry "),
        Style::new().bold(),
    ));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_password_fields(lines: &mut Vec<Line>, form: &AddForm) {
    let rows: [(&str, &str, bool); 5] = [
        ("Title", &form.title, false),
        ("UserName", &form.username, false),
        ("Password", &form.password, true),
        ("URL", &form.url, false),
        ("Notes", &form.notes, false),
    ];
    for (i, (label, value, protected)) in rows.iter().enumerate() {
        let row = i + 1;
        let selected = row == form.field;
        let shown = if *protected && !value.is_empty() {
            "•".repeat(value.len().min(24))
        } else {
            value.to_string()
        };
        let style = if selected {
            Style::new()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        let cursor = if selected { "█" } else { "" };
        let display = if shown.is_empty() {
            cursor.to_string()
        } else {
            shown
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:>9}: ", label), style),
            Span::styled(display, style),
        ]));
    }
}

fn render_twofa_fields(lines: &mut Vec<Line>, form: &AddForm) {
    let rows: [(&str, &str, bool); 7] = [
        ("Issuer", &form.issuer, false),
        ("Account", &form.account, false),
        ("Secret/URI", &form.secret_or_uri, false),
        ("", "", false), // kind selector
        ("Digits", &form.digits, false),
        ("Period", &form.period, false),
        ("Counter", &form.counter, false),
    ];
    for (i, (label, value, _)) in rows.iter().enumerate() {
        let row = i + 1;
        let selected = row == form.field;
        let style = if selected {
            Style::new()
                .bg(ratatui::style::Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        if row == 4 {
            // OtpKind selector.
            let display = form.otp_kind.as_str();
            let arrow = if selected { " ← →" } else { "" };
            lines.push(Line::from(vec![
                Span::styled("     Kind: ", style),
                Span::styled(format!("{display}{arrow}"), style),
            ]));
        } else {
            let display = if value.is_empty() && selected {
                "█".to_string()
            } else {
                value.to_string()
            };
            let label_str = if label.is_empty() { "        " } else { label };
            lines.push(Line::from(vec![
                Span::styled(format!("{:>9}: ", label_str), style),
                Span::styled(display, style),
            ]));
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let [_, vy, _] = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .areas(r);
    let [_, hx, _] = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .areas(vy);
    hx
}

fn count_entries(g: &onepass_engine::db::Group) -> usize {
    g.entries.len() + g.groups.iter().map(count_entries).sum::<usize>()
}
