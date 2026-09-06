//! TUI rendering.

use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, TableState,
};
use ratatui::Frame;

use crate::app::{seconds_remaining, App, Mode, PathAction};
use onepass_engine::db::entry_otp;

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(1),
    ])
    .areas(f.area());

    draw_header(f, app, header);

    let [list_area, details_area] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(body);
    draw_list(f, app, list_area);
    draw_details(f, app, details_area);

    draw_footer(f, app, footer);

    match app.mode {
        Mode::Search => input_popup(f, "Search (Enter to apply, Esc cancel)", &app.input),
        Mode::AddOtp => input_popup(
            f,
            "Add 2FA — paste otpauth:// URI (Enter add, Esc cancel)",
            &app.input,
        ),
        Mode::InputPath => {
            let title = match app.input_action {
                Some(PathAction::Import) => {
                    "Import — file path (Aegis JSON / URI list / migration URI)"
                }
                _ => "Export — file path (.json = Aegis, other = otpauth URI list)",
            };
            input_popup(f, title, &app.input);
        }
        Mode::AddEntry => form_popup(f, app),
        Mode::Confirm => confirm_popup(f, app),
        Mode::Normal => {}
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let dirty_mark = if app.dirty { "*" } else { "" };
    let filter_mark = if app.filter.is_empty() {
        String::new()
    } else {
        format!("  filter: {}", app.filter)
    };
    let line = Line::from(vec![
        Span::styled(" OnePass ", Style::new().bold().bg(ratatui::style::Color::Cyan).fg(ratatui::style::Color::Black)),
        Span::raw(format!(
            " {}{} — {} entries{} ",
            app.file,
            dirty_mark,
            count_entries(&app.vault.root),
            filter_mark
        )),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let list = app.filtered_entries();

    let rows = list
        .iter()
        .enumerate()
        .map(|(i, (path, e))| {
            let otp_cell = entry_otp(e)
                .map(|p| match p.kind {
                    onepass_engine::otp::OtpKind::Hotp => "HOTP".to_string(),
                    other => format!(
                        "{} {}s",
                        if matches!(other, onepass_engine::otp::OtpKind::Steam) {
                            "Steam"
                        } else {
                            "TOTP"
                        },
                        seconds_remaining(p.period)
                    ),
                })
                .unwrap_or_default();
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(path.clone()),
                Cell::from(e.title().unwrap_or("").to_string()),
                Cell::from(e.username().unwrap_or("").to_string()),
                Cell::from(otp_cell),
            ])
        })
        .collect::<Vec<_>>();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(16),
        Constraint::Min(12),
        Constraint::Min(14),
        Constraint::Length(11),
    ];

    let title = if app.mode == Mode::Search {
        format!(" Entries — search: {}█ ", app.input)
    } else if !app.filter.is_empty() {
        format!(" Entries — filter: {} ", app.filter)
    } else {
        " Entries ".to_string()
    };

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["#", "Group", "Title", "UserName", "OTP"])
                .style(Style::new().bold().underlined()),
        )
        .block(Block::new().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::new().bg(ratatui::style::Color::DarkGray).add_modifier(Modifier::BOLD),
        )
        .column_spacing(1);

    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_details(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    match app.selected_entry() {
        Some(e) => {
            let secret_style = if app.reveal {
                Style::new().fg(ratatui::style::Color::LightRed).bold()
            } else {
                Style::new().fg(ratatui::style::Color::DarkGray)
            };

            for field in &e.fields {
                let shown = if field.protected && !app.reveal {
                    "•".repeat(field.value.len().min(24))
                } else {
                    field.value.clone()
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{:>9}: ", field.key), Style::new().bold()),
                    Span::styled(shown, secret_style),
                ]));
            }

            if let Some(params) = entry_otp(e) {
                if let Ok(code) = params.generate(now_secs()) {
                    lines.push(Line::from("─".repeat(30)));
                    let remain = seconds_remaining(params.period);
                    lines.push(Line::from(vec![
                        Span::styled("     OTP: ", Style::new().bold()),
                        Span::styled(
                            code,
                            Style::new()
                                .fg(ratatui::style::Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!(
                            "  ({}s{})",
                            if params.kind == onepass_engine::otp::OtpKind::Hotp {
                                format!("counter={}", params.counter)
                            } else {
                                format!("{remain}")
                            },
                            if app.reveal {
                                let _ = &params; // secret shown below
                                String::new()
                            } else {
                                String::new()
                            }
                        )),
                    ]));
                    if app.reveal {
                        lines.push(Line::from(vec![
                            Span::styled("  Secret: ", Style::new().bold()),
                            Span::styled(
                                onepass_engine::encoding::base32::encode(&params.secret),
                                secret_style,
                            ),
                        ]));
                    }
                }
            }
        }
        None => {
            lines.push(Line::from("No entries. Press 'a' to add, 't' for 2FA."));
        }
    }

    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(
            " Details ",
            Style::new().bold(),
        ));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let msg = app.message.clone().unwrap_or_default();
    let help = " q quit │ s save │ a add │ t add 2FA │ d delete │ / search │ i import │ e export │ r reveal ";
    let line = if msg.is_empty() {
        Line::from(Span::styled(help, Style::new().dim()))
    } else {
        Line::from(Span::styled(format!(" {msg} "), Style::new().fg(ratatui::style::Color::Black).bg(ratatui::style::Color::Yellow)))
    };
    f.render_widget(Paragraph::new(line), area);
}

fn input_popup(f: &mut Frame, title: &str, input: &str) {
    let area = centered_rect(70, 8, f.area());
    f.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), Style::new().bold()));
    let text = Paragraph::new(format!("{input}█")).block(block);
    f.render_widget(text, area);
}

fn confirm_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 12, f.area());
    f.render_widget(Clear, area);
    let text = match app.confirm {
        Some(crate::app::ConfirmAction::Quit) => {
            "Unsaved changes — save before quitting?\n\n  [y] save & quit    [n] discard    [Esc] stay"
        }
        _ => "Delete the selected entry?\n\n  [y] delete    [n/Esc] cancel",
    };
    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(" Confirm ", Style::new().bold().fg(ratatui::style::Color::Yellow)));
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn form_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(64, 46, f.area());
    f.render_widget(Clear, area);

    let form = &app.form;
    let fields: [(&str, &String); 5] = [
        ("Title", &form.title),
        ("UserName", &form.username),
        ("Password", &form.password),
        ("URL", &form.url),
        ("Notes", &form.notes),
    ];

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "↑/↓ or Tab switch field · Enter submit · Esc cancel",
        Style::new().dim(),
    )));
    lines.push(Line::from(""));
    for (i, (name, value)) in fields.iter().enumerate() {
        let selected = i == form.field;
        let shown = if *name == "Password" && !value.is_empty() {
            "•".repeat(value.len().min(24))
        } else {
            value.as_str().to_string()
        };
        let style = if selected {
            Style::new().bg(ratatui::style::Color::DarkGray).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<9}: ", name), style),
            Span::styled(
                if shown.is_empty() && selected { "█".to_string() } else if shown.is_empty() { "—".to_string() } else { shown },
                style,
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Leave Password empty to auto-generate a strong one.",
        Style::new().dim(),
    )));

    let block = Block::new()
        .borders(Borders::ALL)
        .title(Span::styled(" Add Entry ", Style::new().bold()));
    f.render_widget(Paragraph::new(lines).block(block), area);
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
    g.entries.len()
        + g.groups.iter().map(count_entries).sum::<usize>()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Renders a small OTP gauge (unused placeholder kept for the gauge widget).
#[allow(dead_code)]
fn otp_gauge(f: &mut Frame, area: Rect, period: u64) {
    let remain = seconds_remaining(period);
    let ratio = if period == 0 { 0.0 } else { remain as f64 / period as f64 };
    let gauge = Gauge::default()
        .gauge_style(Style::new().fg(ratatui::style::Color::LightGreen))
        .ratio(ratio);
    f.render_widget(gauge, area);
}
