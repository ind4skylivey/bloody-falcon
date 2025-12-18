use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use tokio::task::JoinHandle;

use crate::{
    core::{
        engine::Engine,
        error::FalconError,
        signal::{Severity, Signal},
        signal_utils::recon_to_signals,
    },
    ui::app::{App, Status, Target},
};

pub async fn run_tui(
    engine: Arc<Engine>,
    mut app: App,
    use_cache: bool,
    _scope: Option<Arc<crate::core::scope::ClientScope>>,
    demo_mode: bool,
) -> Result<(), FalconError> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut scan_task: Option<(
        usize,
        String,
        JoinHandle<Result<crate::core::engine::ReconResult, FalconError>>,
    )> = None;

    loop {
        terminal.draw(|f| draw_ui(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') => {
                        if !app.signals.is_empty() {
                            app.show_signal_modal = !app.show_signal_modal;
                            app.modal_scroll = 0;
                        }
                    }
                    KeyCode::Char('f') => {
                        app.filter_severity = cycle_severity(app.filter_severity.clone());
                        app.selected_signal = 0;
                        app.modal_scroll = 0;
                    }
                    KeyCode::Char('t') => {
                        app.filter_tag = cycle_tag(app.filter_tag.clone());
                        app.selected_signal = 0;
                        app.modal_scroll = 0;
                    }
                    KeyCode::Char(']') => {
                        let total = filtered_signals(&app).len().max(1);
                        if total > 0 {
                            app.selected_signal = (app.selected_signal + 1) % total;
                            app.modal_scroll = 0;
                        }
                    }
                    KeyCode::Char('[') => {
                        let total = filtered_signals(&app).len().max(1);
                        if total > 0 {
                            if app.selected_signal == 0 {
                                app.selected_signal = total.saturating_sub(1);
                            } else {
                                app.selected_signal -= 1;
                            }
                            app.modal_scroll = 0;
                        }
                    }
                    KeyCode::Up => {
                        if app.show_signal_modal {
                            app.modal_scroll = app.modal_scroll.saturating_sub(1);
                        }
                    }
                    KeyCode::Down => {
                        if app.show_signal_modal {
                            app.modal_scroll = app.modal_scroll.saturating_add(1);
                        }
                    }
                    KeyCode::Enter => {
                        if app.input.trim().is_empty() {
                            if app.targets.is_empty() {
                                app.add_target("shadow".to_string());
                            }
                            if scan_task.is_none() {
                                if let Some((idx, id)) = app.start_scan() {
                                    let engine = engine.clone();
                                    let scan_id = id.clone();
                                    let handle = tokio::spawn(async move {
                                        engine.scan_username(&scan_id, use_cache).await
                                    });
                                    scan_task = Some((idx, id, handle));
                                }
                            }
                        } else {
                            app.add_target(app.input.clone());
                            app.input.clear();
                        }
                    }
                    KeyCode::Char(c) => app.input.push(c),
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Tab => app.next_target(),
                    _ => {}
                }
            }
        }

        // Async scan completion handling
        if let Some((idx, id, handle)) = scan_task.take() {
            if handle.is_finished() {
                match handle.await {
                    Ok(Ok(outcome)) => {
                        let sigs = recon_to_signals(&id, &outcome, &engine, demo_mode);
                        app.add_signals(sigs);
                        app.complete_scan(idx, outcome);
                    }
                    Ok(Err(err)) => app.fail_scan(idx, &err.to_string()),
                    Err(join_err) => app.fail_scan(idx, &join_err.to_string()),
                }
            } else {
                scan_task = Some((idx, id, handle));
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // header
                Constraint::Percentage(20),
                Constraint::Percentage(25),
                Constraint::Percentage(18), // signals
                Constraint::Percentage(20),
                Constraint::Length(7),
            ]
            .as_ref(),
        )
        .split(f.size());

    // Header
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" 🦅 ", Style::default().fg(Color::Red)),
        Span::styled(
            "BLOODY-FALCON",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" v1.0 ", Style::default().fg(Color::Yellow)),
        Span::styled("348 PLATFORMS", Style::default().fg(Color::Cyan)),
        Span::raw(" | ENTER=SCAN "),
        Span::styled(
            format!("NEW {}", app.new_signals_count),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    f.render_widget(title, chunks[0]);

    // Targets list
    let target_items: Vec<ListItem> = app
        .targets
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let status_color = match t.status {
                Status::Scanning => Color::Yellow,
                Status::Found => Color::Green,
                Status::Empty => Color::White,
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:2}", i), Style::default().fg(Color::Gray)),
                Span::raw(" | "),
                Span::styled(&t.id, Style::default().fg(status_color)),
                Span::raw(" ["),
                Span::styled(
                    format!("Hits: {}", t.hits),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("]"),
            ]))
        })
        .collect();

    let targets = List::new(target_items)
        .block(
            Block::default()
                .title(" 🦅 ACTIVE TARGETS (TAB to switch) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));
    f.render_widget(targets, chunks[1]);

    // Intel feed
    let placeholder = Target {
        id: "No Target".to_string(),
        label: None,
        status: Status::Empty,
        hits: 0,
        emails: vec![],
        platforms: vec![],
        failed: vec![],
        restricted: vec![],
        rate_limited: vec![],
    };
    let current = app.targets.get(app.current_target).unwrap_or(&placeholder);

    let mut intel_lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(Color::White)),
            Span::styled(
                &current.id,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Label: ", Style::default().fg(Color::White)),
            Span::styled(
                current.label.as_deref().unwrap_or("None"),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled(
                current.status.to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled("Hits: ", Style::default().fg(Color::White)),
            Span::styled(current.hits.to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![Span::styled(
            "Emails:",
            Style::default().fg(Color::White),
        )]),
    ];

    if current.emails.is_empty() {
        intel_lines.push(Line::from(vec![Span::styled(
            "None recorded",
            Style::default().fg(Color::DarkGray),
        )]));
    } else {
        for email in &current.emails {
            intel_lines.push(Line::from(vec![Span::styled(
                email,
                Style::default().fg(Color::Magenta),
            )]));
        }
    }

    let platform_line = if current.platforms.is_empty() {
        "None".to_string()
    } else {
        current.platforms.join(", ")
    };

    intel_lines.push(Line::from(vec![
        Span::styled("Hits: ", Style::default().fg(Color::White)),
        Span::styled(platform_line, Style::default().fg(Color::Green)),
    ]));

    if !current.restricted.is_empty() {
        intel_lines.push(Line::from(vec![
            Span::styled("Restricted: ", Style::default().fg(Color::White)),
            Span::styled(
                current.restricted.join(", "),
                Style::default().fg(Color::Yellow),
            ),
        ]));
    }

    if !current.rate_limited.is_empty() {
        intel_lines.push(Line::from(vec![
            Span::styled("Rate limited: ", Style::default().fg(Color::White)),
            Span::styled(
                current.rate_limited.join(", "),
                Style::default().fg(Color::Magenta),
            ),
        ]));
    }

    if !current.failed.is_empty() {
        intel_lines.push(Line::from(vec![
            Span::styled("Failed: ", Style::default().fg(Color::White)),
            Span::styled(current.failed.join(" | "), Style::default().fg(Color::Red)),
        ]));
    }

    let intel = Paragraph::new(intel_lines).block(
        Block::default()
            .title(" 🛡️ INTEL FEED ")
            .borders(Borders::ALL),
    );
    f.render_widget(intel, chunks[2]);

    // Signals pane
    let filtered = filtered_signals(app);
    let signal_items: Vec<ListItem> = filtered
        .iter()
        .enumerate()
        .take(6)
        .map(|(idx, s)| {
            let color = severity_color(&s.severity);
            let title = format!("{:?}", s.signal_type);
            let subject = &s.subject;
            let sev = format!("{:?}", s.severity);
            let tag_line = if s.tags.is_empty() {
                "".to_string()
            } else {
                format!(" [{}]", s.tags.join(","))
            };
            let line = Line::from(vec![
                Span::styled(
                    title,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(subject, Style::default().fg(Color::White)),
                Span::raw(" "),
                Span::styled(sev, Style::default().fg(color)),
                Span::raw(tag_line),
            ]);
            let mut item = ListItem::new(line);
            if idx == app.selected_signal {
                item = item.style(Style::default().bg(Color::DarkGray));
            }
            item
        })
        .collect();

    let mut title = " 📡 SIGNALS ".to_string();
    if let Some(sev) = &app.filter_severity {
        title.push_str(&format!("| {:?} ", sev));
    }
    if let Some(tag) = &app.filter_tag {
        title.push_str(&format!("| tag={} ", tag));
    }
    let signals = List::new(signal_items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(signals, chunks[3]);

    // Scan progress
    if app.scanning {
        let progress = Gauge::default()
            .block(
                Block::default()
                    .title(" 🔍 SCAN PROGRESS ")
                    .borders(Borders::ALL),
            )
            .gauge_style(Style::default().fg(Color::Yellow))
            .ratio(0.7);
        f.render_widget(progress, chunks[4]);
    } else {
        let progress = Paragraph::new("Press ENTER to start scan").block(
            Block::default()
                .title(" 🔍 SCAN ENGINE ")
                .borders(Borders::ALL),
        );
        f.render_widget(progress, chunks[4]);
    }

    // Input + logs
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
        .split(chunks[5]);

    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .title(" 🎯 ENTER TARGET ID ")
            .borders(Borders::ALL),
    );
    f.render_widget(input, bottom_chunks[0]);

    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .take(6)
        .map(|log| {
            ListItem::new(Line::from(vec![
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" "),
                Span::raw(log),
            ]))
        })
        .collect();

    let logs = List::new(log_items).block(
        Block::default()
            .title(" 📜 SYSTEM LOGS ")
            .borders(Borders::ALL),
    );
    f.render_widget(logs, bottom_chunks[1]);

    // Modal overlay for signal details
    if app.show_signal_modal && !app.signals.is_empty() {
        if let Some(sig) = selected_signal(app) {
            let area = centered_rect(70, 50, f.size());
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Signal: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", sig.signal_type),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Subject: ", Style::default().fg(Color::White)),
                    Span::styled(sig.subject.clone(), Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("Severity: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", sig.severity),
                        Style::default().fg(Color::Red),
                    ),
                    Span::raw(" | Confidence: "),
                    Span::styled(sig.confidence.to_string(), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Tags: ", Style::default().fg(Color::White)),
                    Span::styled(sig.tags.join(", "), Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled("Action: ", Style::default().fg(Color::White)),
                    Span::styled(
                        sig.recommended_action.clone(),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Fingerprint: ", Style::default().fg(Color::White)),
                    Span::styled(sig.fingerprint.clone(), Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![Span::styled(
                    "Evidence:",
                    Style::default().fg(Color::White),
                )]),
            ];
            for ev in sig.evidence.iter().take(4) {
                lines.push(Line::from(vec![
                    Span::styled(" - ", Style::default().fg(Color::Gray)),
                    Span::styled(&ev.source, Style::default().fg(Color::Magenta)),
                    Span::raw(" "),
                    Span::styled(
                        ev.url.clone().unwrap_or_else(|| "no-url".to_string()),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
            }
            let height = area.height.saturating_sub(2) as usize;
            let start = app.modal_scroll.min(lines.len().saturating_sub(1));
            let end = (start + height).min(lines.len());
            let view = lines[start..end].to_vec();
            let modal = Paragraph::new(view).block(
                Block::default()
                    .title(" 🔎 SIGNAL DETAIL (s to close, [/] to change) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            f.render_widget(Clear, area);
            f.render_widget(modal, area);
        }
    }
}

fn severity_color(sev: &Severity) -> Color {
    match sev {
        Severity::Low => Color::Blue,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1]);

    horizontal[1]
}

fn selected_signal(app: &App) -> Option<&Signal> {
    let filtered = filtered_signals(app);
    if filtered.is_empty() {
        return None;
    }
    let idx = app.selected_signal.min(filtered.len() - 1);
    filtered.get(idx).copied()
}

fn filtered_signals(app: &App) -> Vec<&Signal> {
    let mut items: Vec<&Signal> = app.signals.iter().rev().collect();
    if let Some(sev) = &app.filter_severity {
        items.retain(|s| &s.severity == sev);
    }
    if let Some(tag) = &app.filter_tag {
        items.retain(|s| s.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)));
    }
    items
}

fn cycle_severity(current: Option<Severity>) -> Option<Severity> {
    match current {
        None => Some(Severity::High),
        Some(Severity::High) => Some(Severity::Medium),
        Some(Severity::Medium) => Some(Severity::Low),
        Some(Severity::Low) => None,
    }
}

fn cycle_tag(current: Option<String>) -> Option<String> {
    let tags = ["paste", "code-leak", "typosquat"];
    match current {
        None => Some(tags[0].to_string()),
        Some(ref t) if t.eq_ignore_ascii_case(tags[0]) => Some(tags[1].to_string()),
        Some(ref t) if t.eq_ignore_ascii_case(tags[1]) => Some(tags[2].to_string()),
        _ => None,
    }
}
