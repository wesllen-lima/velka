use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, Borders, Clear, List, ListItem, Paragraph, Wrap,
};
use ratatui::Frame;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style as SyntectStyle, ThemeSet};
use syntect::parsing::SyntaxSet;

use crate::domain::{Severity, Sin};
use crate::utils::calculate_entropy;

use super::app::{App, Panel, ScanStatus};

pub fn render(f: &mut Frame, app: &App) {
    let size = f.area();

    // Main layout: header, body, footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // body
            Constraint::Length(3), // footer / status
        ])
        .split(size);

    render_header(f, main_chunks[0], app);
    render_body(f, main_chunks[1], app);
    render_footer(f, main_chunks[2], app);

    if app.show_help {
        render_help_overlay(f, size);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let mortal_count = app
        .sins
        .iter()
        .filter(|s| s.severity == Severity::Mortal)
        .count();
    let venial_count = app.sins.len() - mortal_count;

    let status_icon = match app.scan_status {
        ScanStatus::Scanning => "Scanning...",
        ScanStatus::Done => "Complete",
    };

    let header_text = vec![Line::from(vec![
        Span::styled(
            "VELKA ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Dashboard",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled(
            format!("{mortal_count} Mortal"),
            Style::default().fg(Color::Red),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{venial_count} Venial"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  |  "),
        Span::styled(status_icon, Style::default().fg(Color::Cyan)),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Velka Security Scanner "),
    );
    f.render_widget(header, area);
}

fn render_body(f: &mut Frame, area: Rect, app: &App) {
    // Split body: left findings list, right detail/entropy
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_findings_list(f, body_chunks[0], app);

    // Right panel: detail on top, entropy on bottom
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(body_chunks[1]);

    render_detail_panel(f, right_chunks[0], app);
    render_entropy_panel(f, right_chunks[1], app);
}

fn render_findings_list(f: &mut Frame, area: Rect, app: &App) {
    let is_active = app.active_panel == Panel::Findings;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let visible_height = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .sins
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(visible_height)
        .map(|(i, sin)| {
            let severity_icon = match sin.severity {
                Severity::Mortal => Span::styled(
                    "!",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Severity::Venial => Span::styled("~", Style::default().fg(Color::Yellow)),
            };

            let path_short = sin.path.rsplit('/').next().unwrap_or(&sin.path);
            let text = Line::from(vec![
                Span::raw(" "),
                severity_icon,
                Span::raw(" "),
                Span::styled(
                    format!("{:<16}", truncate(&sin.rule_id, 16)),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{}:{}", truncate(path_short, 20), sin.line_number),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);

            if i == app.selected {
                ListItem::new(text).style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                ListItem::new(text)
            }
        })
        .collect();

    let title = format!(" Findings ({}) ", app.sins.len());
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style),
    );

    f.render_widget(list, area);
}

fn render_detail_panel(f: &mut Frame, area: Rect, app: &App) {
    let is_active = app.active_panel == Panel::Detail;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Detail ")
        .border_style(border_style);

    let Some(sin) = app.selected_sin() else {
        let empty = Paragraph::new("No finding selected.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty, area);
        return;
    };

    let inner_height = area.height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();

    // Metadata
    lines.push(Line::from(vec![
        Span::styled("Rule:     ", Style::default().fg(Color::Cyan)),
        Span::styled(
            &sin.rule_id,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Severity: ", Style::default().fg(Color::Cyan)),
        match sin.severity {
            Severity::Mortal => Span::styled(
                "MORTAL",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Severity::Venial => Span::styled("VENIAL", Style::default().fg(Color::Yellow)),
        },
    ]));
    lines.push(Line::from(vec![
        Span::styled("File:     ", Style::default().fg(Color::Cyan)),
        Span::raw(format!("{}:{}", sin.path, sin.line_number)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Desc:     ", Style::default().fg(Color::Cyan)),
        Span::raw(&sin.description),
    ]));

    if let Some(conf) = sin.confidence {
        lines.push(Line::from(vec![
            Span::styled("ML Score: ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("{:.0}%", conf * 100.0), confidence_color(conf)),
        ]));
    }

    if let Some(ref hash) = sin.commit_hash {
        lines.push(Line::from(vec![
            Span::styled("Commit:   ", Style::default().fg(Color::Cyan)),
            Span::raw(hash.clone()),
        ]));
    }

    if let Some(true) = sin.verified {
        lines.push(Line::from(vec![
            Span::styled("Verified: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                "YES (live credential)",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "--- Code Context ---",
        Style::default().fg(Color::DarkGray),
    )));

    // Syntax highlighted code context
    let highlighted = highlight_context(sin);
    lines.extend(highlighted);

    // Apply scroll
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(app.detail_scroll)
        .take(inner_height)
        .collect();

    let detail = Paragraph::new(visible_lines)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(detail, area);
}

fn render_entropy_panel(f: &mut Frame, area: Rect, app: &App) {
    let is_active = app.active_panel == Panel::Entropy;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Entropy Distribution ")
        .border_style(border_style);

    let Some(sin) = app.selected_sin() else {
        let empty = Paragraph::new("No finding selected.")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty, area);
        return;
    };

    // Build entropy bars from context lines
    let bars: Vec<Bar> = sin
        .context
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let entropy = calculate_entropy(line);
            let label = format!("L{}", i + 1);
            let value = (entropy * 10.0) as u64; // scale to 0-80 range
            let color = if entropy > 5.0 {
                Color::Red
            } else if entropy > 4.0 {
                Color::Yellow
            } else {
                Color::Green
            };
            Bar::default()
                .label(label)
                .value(value)
                .style(Style::default().fg(color))
        })
        .collect();

    if bars.is_empty() {
        // Show snippet entropy only
        let snippet_entropy = calculate_entropy(&sin.snippet);
        let info = Paragraph::new(vec![Line::from(vec![
            Span::styled("Snippet entropy: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{snippet_entropy:.2} bits"),
                entropy_color(snippet_entropy),
            ),
        ])])
        .block(block);
        f.render_widget(info, area);
        return;
    }

    let chart = BarChart::default()
        .block(block)
        .data(BarGroup::default().bars(&bars))
        .bar_width(3)
        .bar_gap(1)
        .max(80);

    f.render_widget(chart, area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let status_text = if let Some((ref msg, _)) = app.status_message {
        Line::from(vec![
            Span::styled(" >> ", Style::default().fg(Color::Green)),
            Span::raw(msg.as_str()),
        ])
    } else {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Cyan)),
            Span::raw(":quit "),
            Span::styled("j/k", Style::default().fg(Color::Cyan)),
            Span::raw(":nav "),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::raw(":panel "),
            Span::styled("r", Style::default().fg(Color::Cyan)),
            Span::raw(":rotate "),
            Span::styled("i", Style::default().fg(Color::Cyan)),
            Span::raw(":ignore "),
            Span::styled("m", Style::default().fg(Color::Cyan)),
            Span::raw(":migrate "),
            Span::styled("Q", Style::default().fg(Color::Cyan)),
            Span::raw(":quarantine "),
            Span::styled("p", Style::default().fg(Color::Cyan)),
            Span::raw(":placeholder "),
            Span::styled("v", Style::default().fg(Color::Cyan)),
            Span::raw(":vault "),
            Span::styled("?", Style::default().fg(Color::Cyan)),
            Span::raw(":help"),
        ])
    };

    let footer = Paragraph::new(status_text)
        .block(Block::default().borders(Borders::ALL).title(" Actions "));
    f.render_widget(footer, area);
}

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = 22u16.min(area.height.saturating_sub(4));

    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let help_lines = vec![
        Line::from(Span::styled(
            "Velka TUI Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  j/Down  ", Style::default().fg(Color::Yellow)),
            Span::raw("Move down"),
        ]),
        Line::from(vec![
            Span::styled("  k/Up    ", Style::default().fg(Color::Yellow)),
            Span::raw("Move up"),
        ]),
        Line::from(vec![
            Span::styled("  Tab     ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch panel"),
        ]),
        Line::from(vec![
            Span::styled("  Enter   ", Style::default().fg(Color::Yellow)),
            Span::raw("Open detail view"),
        ]),
        Line::from(vec![
            Span::styled("  Esc     ", Style::default().fg(Color::Yellow)),
            Span::raw("Back to findings"),
        ]),
        Line::from(vec![
            Span::styled("  g/Home  ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to top"),
        ]),
        Line::from(vec![
            Span::styled("  G/End   ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to bottom"),
        ]),
        Line::from(vec![
            Span::styled("  e       ", Style::default().fg(Color::Yellow)),
            Span::raw("Focus entropy panel"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Quick Actions:",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(vec![
            Span::styled("  r       ", Style::default().fg(Color::Yellow)),
            Span::raw("Rotation guidance"),
        ]),
        Line::from(vec![
            Span::styled("  i       ", Style::default().fg(Color::Yellow)),
            Span::raw("Ignore rule hint"),
        ]),
        Line::from(vec![
            Span::styled("  m       ", Style::default().fg(Color::Yellow)),
            Span::raw("Migration hint"),
        ]),
        Line::from(vec![
            Span::styled("  Q       ", Style::default().fg(Color::Yellow)),
            Span::raw("Quarantine file"),
        ]),
        Line::from(vec![
            Span::styled("  p       ", Style::default().fg(Color::Yellow)),
            Span::raw("Inject placeholder"),
        ]),
        Line::from(vec![
            Span::styled("  v       ", Style::default().fg(Color::Yellow)),
            Span::raw("Vault sync info"),
        ]),
        Line::from(vec![
            Span::styled("  q       ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]),
    ];

    let help = Paragraph::new(help_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help (press any key to close) ")
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help, popup_area);
}

// --- Syntax Highlighting ---

fn highlight_context(sin: &Sin) -> Vec<Line<'static>> {
    let ps = SyntaxSet::load_defaults_newlines();
    let ts = ThemeSet::load_defaults();
    let theme = &ts.themes["base16-ocean.dark"];

    let extension = sin.path.rsplit('.').next().unwrap_or("txt");
    let syntax = ps
        .find_syntax_by_extension(extension)
        .unwrap_or_else(|| ps.find_syntax_plain_text());

    let mut highlighter = HighlightLines::new(syntax, theme);

    let source_lines: Vec<&str> = if sin.context.is_empty() {
        vec![sin.snippet.as_str()]
    } else {
        sin.context.iter().map(String::as_str).collect()
    };

    let sin_line = sin.line_number;
    let context_start = sin_line.saturating_sub(sin.context.len() / 2);

    source_lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let line_num = context_start + i;
            let is_secret_line = line_num == sin_line;

            let line_prefix = format!("{line_num:>4} ");

            let mut spans: Vec<Span<'static>> = Vec::new();

            if is_secret_line {
                spans.push(Span::styled(
                    line_prefix,
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::styled(
                    line_prefix,
                    Style::default().fg(Color::DarkGray),
                ));
            }

            // Use syntect for highlighting
            if let Ok(highlighted) = highlighter.highlight_line(line, &ps) {
                for (style, text) in highlighted {
                    let fg = syntect_to_ratatui_color(style);
                    let mut ratatui_style = Style::default().fg(fg);
                    if is_secret_line {
                        ratatui_style = ratatui_style.bg(Color::Rgb(60, 20, 20));
                    }
                    spans.push(Span::styled(text.to_string(), ratatui_style));
                }
            } else {
                let style = if is_secret_line {
                    Style::default().fg(Color::White).bg(Color::Rgb(60, 20, 20))
                } else {
                    Style::default().fg(Color::White)
                };
                spans.push(Span::styled((*line).to_string(), style));
            }

            Line::from(spans)
        })
        .collect()
}

fn syntect_to_ratatui_color(style: SyntectStyle) -> Color {
    Color::Rgb(style.foreground.r, style.foreground.g, style.foreground.b)
}

fn confidence_color(conf: f32) -> Style {
    if conf > 0.8 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if conf > 0.5 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn entropy_color(entropy: f32) -> Style {
    if entropy > 5.0 {
        Style::default().fg(Color::Red)
    } else if entropy > 4.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}..", &s[..max.saturating_sub(2)])
    }
}
