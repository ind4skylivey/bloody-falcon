use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};

use crate::core::types::{Finding, FindingDisposition, Signal};

pub fn run_tui(signals: Vec<Signal>, findings: Vec<Finding>) -> Result<()> {
    let mut app = App::new(signals, findings);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let tick_rate = Duration::from_millis(200);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| draw(f, &app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up => app.prev(),
                    KeyCode::Down => app.next(),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), terminal::LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

struct App {
    signals: Vec<Signal>,
    findings: Vec<Finding>,
    finding_index: HashMap<String, FindingSummary>,
    selected: usize,
}

#[derive(Clone)]
struct FindingSummary {
    disposition: FindingDisposition,
    severity: String,
    confidence: u8,
    title: String,
}

impl App {
    fn new(signals: Vec<Signal>, findings: Vec<Finding>) -> Self {
        let mut finding_index = HashMap::new();
        for f in &findings {
            for sid in &f.signals {
                finding_index.insert(
                    sid.clone(),
                    FindingSummary {
                        disposition: f.disposition.clone(),
                        severity: format!("{:?}", f.severity),
                        confidence: f.confidence,
                        title: f.title.clone(),
                    },
                );
            }
        }
        Self {
            signals,
            findings,
            finding_index,
            selected: 0,
        }
    }

    fn next(&mut self) {
        if self.signals.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.signals.len();
    }

    fn prev(&mut self) {
        if self.signals.is_empty() {
            return;
        }
        if self.selected == 0 {
            self.selected = self.signals.len() - 1;
        } else {
            self.selected -= 1;
        }
    }
}

fn draw(f: &mut Frame<CrosstermBackend<io::Stdout>>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(1),
            ]
            .as_ref(),
        )
        .split(f.size());

    draw_header(f, chunks[0]);
    draw_body(f, chunks[1], app);
    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect) {
    let title = Paragraph::new("🦅 BLOODY-FALCON v1.0 — READ-ONLY TUI (q to quit)")
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("HEADER"));
    f.render_widget(title, area);
}

fn draw_body(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

    draw_signal_list(f, columns[0], app);
    draw_signal_detail(f, columns[1], app);
}

fn draw_signal_list(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .signals
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let disp = app
                .finding_index
                .get(&s.id)
                .map(|fs| format!("{:?}", fs.disposition))
                .unwrap_or_else(|| "Digest".to_string());
            let sev = format!("{:?}", s.severity);
            let line = Line::from(vec![
                Span::styled(format!("{} ", i + 1), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", s.signal_type),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(" "),
                Span::raw(s.subject.clone()),
                Span::raw(" "),
                Span::styled(sev, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::styled(disp, Style::default().fg(Color::Magenta)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Signals"))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("➤ ");
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_signal_detail(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let sig_opt = app.signals.get(app.selected);
    let content = if let Some(sig) = sig_opt {
        let mut lines = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("{:?} — {}", sig.signal_type, sig.subject),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!(
            "Severity: {:?} | Confidence: {} | Source: {}",
            sig.severity, sig.confidence, sig.source
        )));
        if let Some(fs) = app.finding_index.get(&sig.id) {
            lines.push(Line::from(format!(
                "Disposition: {:?} | Finding: {} ({} @ {})",
                fs.disposition, fs.title, fs.severity, fs.confidence
            )));
        } else {
            lines.push(Line::from("Disposition: Digest (no finding)"));
        }
        lines.push(Line::from(format!("Evidence: {}", sig.evidence_ref)));
        lines.push(Line::from(format!(
            "Indicators: {}",
            sig.indicators
                .iter()
                .map(|i| i.0.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )));
        lines.push(Line::from(format!("Rationale: {}", sig.rationale)));
        if let Some(reason) = &sig.suppression_reason {
            lines.push(Line::from(format!("Suppression: {}", reason)));
        }
        Paragraph::new(lines)
    } else {
        Paragraph::new("No signals").style(Style::default().fg(Color::DarkGray))
    };

    let block = Block::default().borders(Borders::ALL).title("Details");
    f.render_widget(content.block(block), area);
}

fn draw_footer(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect) {
    let line = Line::from(vec![
        Span::styled("NAV: ↑/↓ ", Style::default().fg(Color::Cyan)),
        Span::raw(" | "),
        Span::styled("QUIT: q/ESC", Style::default().fg(Color::Red)),
    ]);
    let footer = Paragraph::new(line).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, area);
}
