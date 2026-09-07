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

    // Modal popups — all centered (search, import/export, form, confirm, help).
    match app.mode {
        Mode::Search => search_popup(f, app),
        Mode::InputPath => input_path_popup(f, app),
        Mode::AddEntry => form_popup(f, app),
        Mode::Confirm => confirm_popup(f, app),
        Mode::ChangePassword => change_password_popup(f, app),
        Mode::Help => help_popup(f, app),
        Mode::DetailsEdit => {
            // Inline edit is handled directly in the details panel (Enter opens edit);
            // no extra centered popup needed — the details panel itself is the editor.
        }
        Mode::Normal => {}
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let dirty = if app.dirty { " *" } else { "" };
    let marked = if app.marked.is_empty() {
        String::new()
    } else {
        format!("  [x{}]", app.marked.len())
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
                "x"
            } else {
                " "
            };
            let kind = if entry_otp(e).is_some() { "O" } else { "P" };
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
    let title = if !app.filter.is_empty() {
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
        Panel::List => " List: Space multi / a add / d delete / Tab Details ",
        Panel::Details => " Details: j/k navigate / c copy / v paste / Enter edit / Tab List ",
    };
    let common = " s save | / search | i import | e export | r reveal | ? help | q quit ";
    let text = format!("{panel_hint}| {common}");
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

#[allow(dead_code)]
fn search_popup(f: &mut Frame, app: &App) {
    let area = input_box(70, f.area());
    f.render_widget(Clear, area);
    let text = Paragraph::new(format!("{}█", app.input)).block(
        Block::new()
            .borders(Borders::ALL)
            .title(Span::styled(" Search ", Style::new().bold())),
    );
    // Footer hint in a second line inside the box for visibility.
    f.render_widget(text, area);
}

fn input_path_popup(f: &mut Frame, app: &App) {
    let area = input_box(70, f.area());
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
                ("Tab", "switch List / Details panel"),
                ("?", "open / close this help"),
                ("s", "save vault to disk"),
                ("P", "change master password (in memory; press s to write)"),
                ("q", "quit (unsaved changes confirm; clean exit saves)"),
                ("Esc", "clear filter / return to Normal"),
            ],
        ),
        (
            "List Panel",
            vec![
                ("j/k", "navigate up/down"),
                ("g/G", "jump to top / bottom"),
                ("Space", "multi-select toggle"),
                ("a", "add password entry"),
                ("t", "add 2FA entry"),
                ("d", "delete current / all marked entries"),
                ("Enter", "edit selected entry"),
                ("u / p / U / o", "copy username / password / URL / OTP code"),
                ("r", "reveal/hide password (auto-hide 15s)"),
            ],
        ),
        (
            "Details Panel",
            vec![
                ("j/k", "navigate fields"),
                ("c", "copy current field to clipboard"),
                ("v", "paste clipboard content"),
                ("Enter", "switch to List and edit selected entry"),
                ("r", "reveal/hide password"),
            ],
        ),
        (
            "Filter / Import / Export",
            vec![
                ("/", "start live filter search"),
                ("i", "import 2FA (Aegis JSON / URI list / Google migration)"),
                ("e", "export 2FA (no marked→all; marked→only marked)"),
                ("F5", "refresh OTP display"),
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
    // Split popup vertically: form fields (top) and fixed hint footer (bottom).
    let is_edit = app.form.editing_uuid.is_some();
    let block_outer = Block::new().borders(Borders::ALL).title(Span::styled(
        format!(" {} Entry ", if is_edit { "Edit" } else { "Add" }),
        Style::new().bold(),
    ));
    let inner = block_outer.inner(area);
    f.render_widget(block_outer, area);

    let [fields_area, hint_area] =
        Layout::vertical([Constraint::Min(8), Constraint::Length(2)]).areas(inner);

    let form = &app.form;
    let mut lines: Vec<Line> = Vec::new();

    // Body rows (type selector + fields).
    // Row 0: type selector.
    let selector_left = if form.field == 0 { " ▸ " } else { "   " };
    let type_display = match form.kind {
        AddFormKind::Password => {
            if form.field == 0 {
                "Password \u{2190} \u{2192} 2FA"
            } else {
                "Password"
            }
        }
        AddFormKind::TwoFa => {
            if form.field == 0 {
                "Password \u{2190} \u{2192} 2FA"
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

    match form.kind {
        AddFormKind::Password => render_password_fields(&mut lines, form),
        AddFormKind::TwoFa => render_twofa_fields(&mut lines, form),
    }

    // Render the scrollable field list to the top area.
    f.render_widget(Paragraph::new(lines), fields_area);

    // Render the fixed hint footer to the bottom area, always visible.
    let hint = match form.kind {
        AddFormKind::Password => "Tab/Up/Down navigate | Enter submit | Esc cancel",
        AddFormKind::TwoFa => {
            "Tab/Up/Down navigate | \u{2190}\u{2192} select Type/Kind | Enter submit | Esc cancel"
        }
    };
    let hint_block = Block::new()
        .borders(Borders::TOP)
        .title(Span::styled(" Keys ", Style::new().dim()));
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::new().dim())).block(hint_block),
        hint_area,
    );
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

/// Fixed 3-line centered box: top border + 1 content line + bottom border.
fn input_box(width_pct: u16, r: Rect) -> Rect {
    let [_, v_box, _] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(2),
    ])
    .areas(r);
    let [_, h_box, _] = Layout::horizontal([
        Constraint::Percentage((100 - width_pct) / 2),
        Constraint::Percentage(width_pct),
        Constraint::Percentage((100 - width_pct) / 2),
    ])
    .areas(v_box);
    h_box
}
fn count_entries(g: &onepass_engine::db::Group) -> usize {
    g.entries.len() + g.groups.iter().map(count_entries).sum::<usize>()
}
