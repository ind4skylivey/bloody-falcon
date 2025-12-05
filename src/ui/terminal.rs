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
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use tokio::task::JoinHandle;

use crate::{
    core::{engine::Engine, error::FalconError},
    ui::app::{App, Status, Target},
};

pub async fn run_tui(
    engine: Arc<Engine>,
    mut app: App,
    use_cache: bool,
) -> Result<(), FalconError> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut scan_task: Option<(usize, JoinHandle<Result<crate::core::engine::ReconResult, FalconError>>)> =
        None;

    loop {
        terminal.draw(|f| draw_ui(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Enter => {
                        if app.input.trim().is_empty() {
                            if app.targets.is_empty() {
                                app.add_target("shadow".to_string());
                            }
                            if scan_task.is_none() {
                                if let Some((idx, id)) = app.start_scan() {
                                    let engine = engine.clone();
                                    let handle = tokio::spawn(async move {
                                        engine.scan_username(&id, use_cache).await
                                    });
                                    scan_task = Some((idx, handle));
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
        if let Some((idx, handle)) = scan_task.take() {
            if handle.is_finished() {
                match handle.await {
                    Ok(Ok(outcome)) => app.complete_scan(idx, outcome),
                    Ok(Err(err)) => app.fail_scan(idx, &err.to_string()),
                    Err(join_err) => app.fail_scan(idx, &join_err.to_string()),
                }
            } else {
                scan_task = Some((idx, handle));
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
                Constraint::Length(3),
                Constraint::Percentage(25),
                Constraint::Percentage(40),
                Constraint::Percentage(25),
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
        Span::raw(" | ENTER=SCAN"),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red)));
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
                Span::styled(format!("Hits: {}", t.hits), Style::default().fg(Color::Cyan)),
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
        status: Status::Empty,
        hits: 0,
        emails: vec![],
        platforms: vec![],
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
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled(current.status.to_string(), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("Hits: ", Style::default().fg(Color::White)),
            Span::styled(current.hits.to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![Span::styled("Emails:", Style::default().fg(Color::White))]),
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
        Span::styled("Platforms: ", Style::default().fg(Color::White)),
        Span::styled(platform_line, Style::default().fg(Color::Yellow)),
    ]));

    let intel = Paragraph::new(intel_lines)
        .block(Block::default().title(" 🛡️ INTEL FEED ").borders(Borders::ALL));
    f.render_widget(intel, chunks[2]);

    // Scan progress
    if app.scanning {
        let progress = Gauge::default()
            .block(Block::default().title(" 🔍 SCAN PROGRESS ").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Yellow))
            .ratio(0.7);
        f.render_widget(progress, chunks[3]);
    } else {
        let progress = Paragraph::new("Press ENTER to start scan")
            .block(Block::default().title(" 🔍 SCAN ENGINE ").borders(Borders::ALL));
        f.render_widget(progress, chunks[3]);
    }

    // Input + logs
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
        .split(chunks[4]);

    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().title(" 🎯 ENTER TARGET ID ").borders(Borders::ALL));
    f.render_widget(input, bottom_chunks[0]);

    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .take(6)
        .map(|log| ListItem::new(Line::from(vec![
            Span::styled("●", Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::raw(log),
        ])))
        .collect();

    let logs = List::new(log_items)
        .block(Block::default().title(" 📜 SYSTEM LOGS ").borders(Borders::ALL));
    f.render_widget(logs, bottom_chunks[1]);
}
