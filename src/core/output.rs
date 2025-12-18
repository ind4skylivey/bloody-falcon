use std::fs;
use std::path::Path;

use chrono::Utc;
use serde::Serialize;

use crate::core::error::FalconError;
use crate::core::signal::{Severity, Signal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Jsonl,
    Sarif,
    Markdown,
}

pub fn write_signals(
    signals: &[Signal],
    format: OutputFormat,
    path: &Path,
) -> Result<(), FalconError> {
    match format {
        OutputFormat::Jsonl => write_jsonl(signals, path),
        OutputFormat::Sarif => write_sarif(signals, path),
        OutputFormat::Markdown => write_markdown(signals, path),
    }
}

fn write_jsonl(signals: &[Signal], path: &Path) -> Result<(), FalconError> {
    let mut lines = String::new();
    for sig in signals {
        let json = serde_json::to_string(sig).map_err(|_| FalconError::Unknown)?;
        lines.push_str(&json);
        lines.push('\n');
    }
    fs::write(path, lines).map_err(|e| FalconError::Config(e.to_string()))
}

#[derive(Serialize)]
struct SarifLog<'a> {
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct SarifResult<'a> {
    rule_id: String,
    level: String,
    message: SarifMessage<'a>,
    properties: SarifProperties<'a>,
}

#[derive(Serialize)]
struct SarifMessage<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SarifProperties<'a> {
    subject: String,
    signal_type: String,
    severity: String,
    confidence: u8,
    tags: Vec<String>,
    evidence: &'a [crate::core::signal::Evidence],
    recommended_action: String,
    fingerprint: String,
}

fn write_sarif(signals: &[Signal], path: &Path) -> Result<(), FalconError> {
    let results = signals
        .iter()
        .map(|sig| SarifResult {
            rule_id: format!("{:?}", sig.signal_type),
            level: sarif_level(&sig.severity),
            message: SarifMessage {
                text: &sig.recommended_action,
            },
            properties: SarifProperties {
                subject: sig.subject.clone(),
                signal_type: format!("{:?}", sig.signal_type),
                severity: format!("{:?}", sig.severity),
                confidence: sig.confidence,
                tags: sig.tags.clone(),
                evidence: &sig.evidence,
                recommended_action: sig.recommended_action.clone(),
                fingerprint: sig.fingerprint.clone(),
            },
        })
        .collect();

    let log = SarifLog {
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "bloody-f4lcon".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
            },
            results,
        }],
    };
    let json = serde_json::to_string_pretty(&log).map_err(|_| FalconError::Unknown)?;
    fs::write(path, json).map_err(|e| FalconError::Config(e.to_string()))
}

fn write_markdown(signals: &[Signal], path: &Path) -> Result<(), FalconError> {
    let mut out = String::new();
    out.push_str("# Bloody-F4lcon Signals\n\n");
    out.push_str(&format!("Generated: {}\n\n", Utc::now().to_rfc3339()));
    if signals.is_empty() {
        out.push_str("_No signals generated._\n");
    }
    for sig in signals {
        out.push_str(&format!("## {:?} — {}\n", sig.signal_type, sig.subject));
        out.push_str(&format!(
            "- Severity: {:?}\n- Confidence: {}\n- Tags: {}\n- Fingerprint: {}\n- First seen: {}\n- Last seen: {}\n- Recommended: {}\n",
            sig.severity,
            sig.confidence,
            sig.tags.join(", "),
            sig.fingerprint,
            sig.first_seen.to_rfc3339(),
            sig.last_seen.to_rfc3339(),
            sig.recommended_action
        ));
        if sig.evidence.is_empty() {
            out.push_str("- Evidence: none\n\n");
        } else {
            out.push_str("- Evidence:\n");
            for ev in &sig.evidence {
                out.push_str(&format!(
                    "  - {} @ {} ({}) {}\n",
                    ev.source,
                    ev.observed_at.to_rfc3339(),
                    ev.url.as_deref().unwrap_or("no-url"),
                    ev.note.as_deref().unwrap_or("")
                ));
            }
            out.push('\n');
        }
    }
    fs::write(path, out).map_err(|e| FalconError::Config(e.to_string()))
}

fn sarif_level(sev: &Severity) -> String {
    match sev {
        Severity::High => "error".into(),
        Severity::Medium => "warning".into(),
        Severity::Low => "note".into(),
    }
}
