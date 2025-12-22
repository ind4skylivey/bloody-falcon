use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};
use serde::Serialize;

use crate::core::types::{Finding, FindingDisposition, Severity, Signal};

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
                    KeyCode::Char('f') => app.cycle_severity_filter(),
                    KeyCode::Char('d') => app.cycle_disposition_filter(),
                    KeyCode::Char('t') => app.cycle_tag_filter(),
                    KeyCode::Char('i') => app.toggle_investigating(),
                    KeyCode::Char('e') => app.export_view(),
                    KeyCode::Char('?') => app.toggle_help(),
                    KeyCode::Enter => app.toggle_detail(),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
            app.tick = app.tick.wrapping_add(1);
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), terminal::LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

#[derive(Clone)]
#[allow(dead_code)]
struct FindingSummary {
    disposition: FindingDisposition,
    #[allow(dead_code)]
    severity: Severity,
    #[allow(dead_code)]
    confidence: u8,
    #[allow(dead_code)]
    title: String,
}

struct App {
    signals: Vec<Signal>,
    #[allow(dead_code)]
    findings: Vec<Finding>,
    finding_lookup: HashMap<String, FindingSummary>,
    finding_map: HashMap<String, Finding>,
    signal_to_findings: HashMap<String, Vec<String>>,
    filtered_indices: Vec<usize>,
    selected: usize,
    filter_severity: Option<Severity>,
    filter_disposition: Option<FindingDisposition>,
    filter_tag: Option<String>,
    status: String,
    show_detail: bool,
    show_help: bool,
    investigating: HashSet<String>,
    tick: usize,
}

#[derive(Serialize)]
struct ExportBundle<'a> {
    generated_at: String,
    filters: ExportFilters<'a>,
    investigating_overrides: Vec<String>,
    signals: Vec<&'a Signal>,
    findings: Vec<&'a Finding>,
}

#[derive(Serialize)]
struct ExportFilters<'a> {
    severity: Option<&'a str>,
    disposition: Option<&'a str>,
    tag: Option<&'a str>,
}

impl App {
    fn new(signals: Vec<Signal>, findings: Vec<Finding>) -> Self {
        let mut signal_to_findings: HashMap<String, Vec<String>> = HashMap::new();
        let mut finding_lookup = HashMap::new();
        let mut finding_map = HashMap::new();

        for f in &findings {
            let summary = FindingSummary {
                disposition: f.disposition.clone(),
                severity: f.severity.clone(),
                confidence: f.confidence,
                title: f.title.clone(),
            };
            finding_lookup.insert(f.id.clone(), summary);
            finding_map.insert(f.id.clone(), f.clone());
            for sid in &f.signals {
                signal_to_findings
                    .entry(sid.clone())
                    .or_default()
                    .push(f.id.clone());
            }
        }

        let mut app = Self {
            signals,
            findings,
            finding_lookup,
            finding_map,
            signal_to_findings,
            filtered_indices: Vec::new(),
            selected: 0,
            filter_severity: None,
            filter_disposition: None,
            filter_tag: None,
            status: "↑/↓ move | f severity | d disposition | t tag | i mark investigate | e export | Enter details | q quit".to_string(),
            show_detail: false,
            show_help: false,
            investigating: HashSet::new(),
            tick: 0,
        };
        app.refresh_filtered();
        app
    }

    fn cycle_severity_filter(&mut self) {
        self.filter_severity = match self.filter_severity {
            None => Some(Severity::Low),
            Some(Severity::Low) => Some(Severity::Medium),
            Some(Severity::Medium) => Some(Severity::High),
            Some(Severity::High) => Some(Severity::Critical),
            Some(Severity::Critical) => None,
        };
        self.refresh_filtered();
    }

    fn cycle_disposition_filter(&mut self) {
        self.filter_disposition = match self.filter_disposition {
            None => Some(FindingDisposition::Alert),
            Some(FindingDisposition::Alert) => Some(FindingDisposition::Investigate),
            Some(FindingDisposition::Investigate) => Some(FindingDisposition::Digest),
            Some(FindingDisposition::Digest) => Some(FindingDisposition::Suppressed),
            Some(FindingDisposition::Suppressed) => None,
        };
        self.refresh_filtered();
    }

    fn cycle_tag_filter(&mut self) {
        let mut tags: Vec<String> = self.signals.iter().flat_map(|s| s.tags.clone()).collect();
        tags.sort_by_key(|a| a.to_lowercase());
        tags.dedup();
        if tags.is_empty() {
            self.status = "no tags available in data".to_string();
            return;
        }
        self.filter_tag = match &self.filter_tag {
            None => Some(tags[0].clone()),
            Some(current) => {
                let pos = tags
                    .iter()
                    .position(|t| t.eq_ignore_ascii_case(current))
                    .unwrap_or(0);
                let next = (pos + 1) % tags.len();
                if next == 0 {
                    None
                } else {
                    Some(tags[next].clone())
                }
            }
        };
        self.refresh_filtered();
    }

    fn refresh_filtered(&mut self) {
        self.filtered_indices.clear();
        for (idx, sig) in self.signals.iter().enumerate() {
            if self.matches_filters(sig) {
                self.filtered_indices.push(idx);
            }
        }
        if self.filtered_indices.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.filtered_indices.len() {
            self.selected = self.filtered_indices.len() - 1;
        }
    }

    fn matches_filters(&self, sig: &Signal) -> bool {
        if let Some(sev) = &self.filter_severity {
            if &sig.severity != sev {
                return false;
            }
        }
        if let Some(fd) = &self.filter_disposition {
            if &self.disposition_for_signal(sig) != fd {
                return false;
            }
        }
        if let Some(tag) = &self.filter_tag {
            if !sig
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(tag.as_str()))
            {
                return false;
            }
        }
        true
    }

    fn disposition_for_signal(&self, sig: &Signal) -> FindingDisposition {
        if let Some(fids) = self.signal_to_findings.get(&sig.id) {
            for fid in fids {
                if self.investigating.contains(fid) {
                    return FindingDisposition::Investigate;
                }
                if let Some(summary) = self.finding_lookup.get(fid) {
                    // Prefer highest priority: Alert > Investigate > Digest > Suppressed
                    match summary.disposition {
                        FindingDisposition::Alert => return FindingDisposition::Alert,
                        FindingDisposition::Investigate => return FindingDisposition::Investigate,
                        FindingDisposition::Digest => return FindingDisposition::Digest,
                        FindingDisposition::Suppressed => continue,
                    }
                }
            }
        }
        FindingDisposition::Digest
    }

    fn prev(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        if self.selected == 0 {
            self.selected = self.filtered_indices.len() - 1;
        } else {
            self.selected -= 1;
        }
    }

    fn next(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.filtered_indices.len();
    }

    fn current_signal(&self) -> Option<&Signal> {
        self.filtered_indices
            .get(self.selected)
            .and_then(|idx| self.signals.get(*idx))
    }

    fn current_findings(&self) -> Vec<&Finding> {
        let Some(sig) = self.current_signal() else {
            return vec![];
        };
        self.signal_to_findings
            .get(&sig.id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.finding_map.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn toggle_detail(&mut self) {
        self.show_detail = !self.show_detail;
        if self.show_detail {
            self.show_help = false;
        }
    }

    fn toggle_investigating(&mut self) {
        let finding_ids: Vec<String> = self
            .current_findings()
            .iter()
            .map(|f| f.id.clone())
            .collect();
        if finding_ids.is_empty() {
            self.status = "no finding linked to signal; nothing to mark".to_string();
            return;
        }
        for fid in finding_ids {
            if self.investigating.remove(&fid) {
                self.status = format!("cleared investigating on {}", fid);
            } else {
                self.investigating.insert(fid.clone());
                self.status = format!("marked {} as investigating (local)", fid);
            }
        }
        self.refresh_filtered();
    }

    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        if self.show_help {
            self.show_detail = false;
            self.status = "help: press ? to close".to_string();
        }
    }

    fn export_view(&mut self) {
        let signals: Vec<&Signal> = self
            .filtered_indices
            .iter()
            .filter_map(|i| self.signals.get(*i))
            .collect();
        let mut finding_ids = HashSet::new();
        for sig in &signals {
            if let Some(ids) = self.signal_to_findings.get(&sig.id) {
                for id in ids {
                    finding_ids.insert(id.clone());
                }
            }
        }
        let findings: Vec<&Finding> = finding_ids
            .iter()
            .filter_map(|id| self.finding_map.get(id))
            .collect();

        let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
        let dir = PathBuf::from("out").join("tui_exports");
        if let Err(e) = fs::create_dir_all(&dir) {
            self.status = format!("export failed: {}", e);
            return;
        }
        let json_path = dir.join(format!("tui_export_{ts}.json"));
        let md_path = dir.join(format!("tui_export_{ts}.md"));

        let disp_binding = self
            .filter_disposition
            .as_ref()
            .map(|d| format!("{:?}", d).to_lowercase());

        let bundle = ExportBundle {
            generated_at: Utc::now().to_rfc3339(),
            filters: ExportFilters {
                severity: self.filter_severity.as_ref().map(|s| match s {
                    Severity::Low => "low",
                    Severity::Medium => "medium",
                    Severity::High => "high",
                    Severity::Critical => "critical",
                }),
                disposition: disp_binding.as_deref(),
                tag: self.filter_tag.as_deref(),
            },
            investigating_overrides: self.investigating.iter().cloned().collect(),
            signals,
            findings,
        };

        let json_out = serde_json::to_string_pretty(&bundle);
        if let Err(e) = json_out {
            self.status = format!("export failed: {}", e);
            return;
        }
        if let Err(e) = fs::write(&json_path, json_out.unwrap()) {
            self.status = format!("export failed: {}", e);
            return;
        }

        let md_content = render_markdown(&bundle);
        if let Err(e) = fs::write(&md_path, md_content) {
            self.status = format!("export failed: {}", e);
            return;
        }

        self.status = format!(
            "exported view → {} and {}",
            json_path.display(),
            md_path.display()
        );
    }
}

fn render_markdown(bundle: &ExportBundle<'_>) -> String {
    let mut out = String::new();
    out.push_str("# BloodyFalcon TUI Export\n\n");
    out.push_str(&format!("Generated: {}\n\n", bundle.generated_at));
    out.push_str("Filters:\n");
    out.push_str(&format!(
        "- severity: {:?}\n- disposition: {:?}\n- tag: {:?}\n\n",
        bundle.filters.severity, bundle.filters.disposition, bundle.filters.tag
    ));

    out.push_str("## Signals\n\n");
    if bundle.signals.is_empty() {
        out.push_str("_none_\n");
    } else {
        out.push_str("| id | type | subject | severity | confidence | disposition |\n");
        out.push_str("|----|------|---------|----------|-------------|-------------|\n");
        for sig in &bundle.signals {
            let disp = "view-only";
            out.push_str(&format!(
                "| {} | {:?} | {} | {:?} | {} | {} |\n",
                sig.id, sig.signal_type, sig.subject, sig.severity, sig.confidence, disp
            ));
        }
    }

    out.push_str("\n## Findings\n\n");
    if bundle.findings.is_empty() {
        out.push_str("_none_\n");
    } else {
        for f in &bundle.findings {
            out.push_str(&format!(
                "- **{}** [{:?}/{}] signals={} {}\n  - rationale: {}\n  - rule_trace: {}\n",
                f.id,
                f.severity,
                f.confidence,
                f.signals.len(),
                if bundle.investigating_overrides.contains(&f.id) {
                    " (marked investigating)"
                } else {
                    ""
                },
                f.rationale,
                if f.rule_trace.is_empty() {
                    "n/a".to_string()
                } else {
                    f.rule_trace.join(" | ")
                }
            ));
        }
    }
    out
}

fn draw(f: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(2),
            ]
            .as_ref(),
        )
        .split(f.size());

    draw_header(f, layout[0], app);
    draw_body(f, layout[1], app);
    draw_footer(f, layout[2], app);

    if app.show_detail {
        draw_detail_modal(f, app);
    }
    if app.show_help {
        draw_help_modal(f);
    }
}

fn draw_header(f: &mut Frame<'_>, area: Rect, app: &App) {
    let spinner_frames = ["◐", "◓", "◑", "◒"];
    let spin = spinner_frames[app.tick % spinner_frames.len()];

    let filters = format!(
        "sev: {} | disp: {} | tag: {}",
        app.filter_severity
            .as_ref()
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "any".to_string()),
        app.filter_disposition
            .as_ref()
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "any".to_string()),
        app.filter_tag
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "any".to_string())
    );
    let badges = vec![
        Span::styled("[DEFENSIVE]", Style::default().fg(Color::Green)),
        Span::raw(" "),
        Span::styled("[READ-ONLY]", Style::default().fg(Color::Yellow)),
        Span::raw(" "),
        Span::styled("[SCOPE-LOCKED]", Style::default().fg(Color::Magenta)),
    ];
    let title = Line::from(vec![
        Span::styled(
            format!("{} 🦅 BLOODY-FALCON v1.0 — READ-ONLY TUI ", spin),
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ),
        Span::raw(" "),
    ]);

    let block = Block::default().borders(Borders::ALL).title("HEADER");
    let lines = vec![title, Line::from(badges), Line::from(filters)];
    let widget = Paragraph::new(lines);
    f.render_widget(widget.block(block), area);
}

fn draw_body(f: &mut Frame<'_>, area: Rect, app: &App) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

    draw_signal_list(f, columns[0], app);
    draw_signal_detail(f, columns[1], app);
}

fn draw_signal_list(f: &mut Frame<'_>, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(visible_idx, sig_idx)| {
            let s = &app.signals[*sig_idx];
            let disp = app.disposition_for_signal(s);
            let sev_color = severity_color(&s.severity);
            let disp_color = disposition_color(&disp);
            let pulse = if app.tick % 8 < 4 {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tags = if s.tags.is_empty() {
                "".to_string()
            } else {
                format!(" [{}]", s.tags.join(","))
            };
            let line = Line::from(vec![
                Span::styled(
                    format!("{:>3} ", visible_idx + 1),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:?}", s.signal_type),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(" "),
                Span::raw(s.subject.clone()),
                Span::raw(" "),
                Span::styled(
                    format!("{:?}", s.severity),
                    Style::default().fg(sev_color).patch(pulse),
                ),
                Span::raw(" "),
                Span::styled(format!("{:?}", disp), Style::default().fg(disp_color)),
                Span::raw(tags),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Signals (filtered)"),
        )
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("➤ ");
    let mut state = ratatui::widgets::ListState::default();
    if !app.filtered_indices.is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_signal_detail(f: &mut Frame<'_>, area: Rect, app: &App) {
    let sig_opt = app.current_signal();
    let content = if let Some(sig) = sig_opt {
        let disp = app.disposition_for_signal(sig);
        let mut lines = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("{:?} — {}", sig.signal_type, sig.subject),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!(
            "Severity: {:?} | Confidence: {} | Source: {} | Disposition: {:?}",
            sig.severity, sig.confidence, sig.source, disp
        )));
        lines.push(Line::from(format!("Tags: {}", sig.tags.join(", "))));
        lines.push(Line::from(format!("Evidence ref: {}", sig.evidence_ref)));
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
        if !sig.recommended_actions.is_empty() {
            lines.push(Line::from("Actions:"));
            for act in &sig.recommended_actions {
                lines.push(Line::from(format!("- {}", act)));
            }
        }
        let findings = app.current_findings();
        if !findings.is_empty() {
            lines.push(Line::from("Findings:"));
            for fnd in findings {
                let mut label = format!(
                    "- {} [{:?}/{}] {:?}",
                    fnd.id, fnd.severity, fnd.confidence, fnd.disposition
                );
                if app.investigating.contains(&fnd.id) {
                    label.push_str(" (investigating)");
                }
                lines.push(Line::from(label));
                if !fnd.rule_trace.is_empty() {
                    lines.push(Line::from(format!(
                        "  trace: {}",
                        fnd.rule_trace.join(" | ")
                    )));
                }
                if let Some(reason) = &fnd.suppression_reason {
                    lines.push(Line::from(format!("  suppression: {}", reason)));
                }
            }
        }
        Paragraph::new(lines)
    } else {
        Paragraph::new("No signals").style(Style::default().fg(Color::DarkGray))
    };

    let block = Block::default().borders(Borders::ALL).title("Details");
    f.render_widget(content.block(block), area);
}

fn draw_footer(f: &mut Frame<'_>, area: Rect, app: &App) {
    let sev_color = app
        .current_signal()
        .map(|s| severity_color(&s.severity))
        .unwrap_or(Color::Cyan);
    let line1 = Line::from(vec![
        Span::styled("Keys: ", Style::default().fg(sev_color)),
        Span::raw("↑/↓ move  "),
        Span::raw("f sev  "),
        Span::raw("d disp  "),
        Span::raw("t tag  "),
        Span::raw("Enter detail  "),
        Span::raw("i investigate  "),
        Span::raw("e export  "),
        Span::raw("? help  "),
        Span::raw("q/ESC quit"),
    ]);
    let line2 = Line::from(vec![
        Span::styled("Status: ", Style::default().fg(Color::Green)),
        Span::styled(&app.status, Style::default().fg(Color::Yellow)),
    ]);
    let footer = Paragraph::new(vec![line1, line2]).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, area);
}

fn draw_detail_modal(f: &mut Frame<'_>, app: &App) {
    let area = centered_rect(80, 80, f.size());
    let mut lines = Vec::new();
    if let Some(sig) = app.current_signal() {
        lines.push(Line::from(Span::styled(
            format!("{} DETAIL", spinner(app.tick)),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "Evidence & Explainability",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!("Evidence ref: {}", sig.evidence_ref)));
        lines.push(Line::from(format!(
            "Policy flags: {}",
            sig.policy_flags.join(", ")
        )));
        let findings = app.current_findings();
        if !findings.is_empty() {
            lines.push(Line::from("Finding explainability:"));
            for fnd in findings {
                lines.push(Line::from(format!("- {}", fnd.title)));
                if !fnd.rule_trace.is_empty() {
                    lines.push(Line::from(format!(
                        "  rules: {}",
                        fnd.rule_trace.join(" | ")
                    )));
                }
                if let Some(blocked) = &fnd.blocked_by {
                    lines.push(Line::from(format!("  blocked by: {}", blocked)));
                }
                if let Some(reason) = &fnd.suppression_reason {
                    lines.push(Line::from(format!("  suppression: {}", reason)));
                }
            }
        }
    } else {
        lines.push(Line::from("No signal selected"));
    }
    let para = Paragraph::new(lines).block(
        Block::default()
            .title("Detail (Enter to close)")
            .borders(Borders::ALL),
    );
    f.render_widget(Clear, area);
    f.render_widget(para, area);
}

fn draw_help_modal(f: &mut Frame<'_>) {
    let area = centered_rect(70, 60, f.size());
    let content = vec![
        Line::from(Span::styled(
            format!("{} Keyboard Shortcuts", spinner_title()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓ : move selection"),
        Line::from("f   : cycle severity filter"),
        Line::from("d   : cycle disposition filter"),
        Line::from("t   : cycle tag filter"),
        Line::from("Enter : toggle detail modal"),
        Line::from("i   : mark/clear investigating (local flag)"),
        Line::from("e   : export current view to JSON+MD (out/tui_exports)"),
        Line::from("?   : toggle this help"),
        Line::from("q/ESC : quit"),
    ];
    let para = Paragraph::new(content).block(
        Block::default()
            .title("Help (press ? to close)")
            .borders(Borders::ALL),
    );
    f.render_widget(Clear, area);
    f.render_widget(para, area);
}

fn severity_color(sev: &Severity) -> Color {
    match sev {
        Severity::Low => Color::Green,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
        Severity::Critical => Color::Magenta,
    }
}

fn disposition_color(d: &FindingDisposition) -> Color {
    match d {
        FindingDisposition::Alert => Color::Red,
        FindingDisposition::Investigate => Color::Yellow,
        FindingDisposition::Digest => Color::Green,
        FindingDisposition::Suppressed => Color::DarkGray,
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

    let vertical = Layout::default()
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

    vertical[1]
}

fn spinner(tick: usize) -> &'static str {
    const FRAMES: [&str; 4] = ["◐", "◓", "◑", "◒"];
    FRAMES[tick % FRAMES.len()]
}

fn spinner_title() -> &'static str {
    "◈"
}
