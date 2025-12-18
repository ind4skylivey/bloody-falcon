use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::core::scope::Scope;
use std::collections::BTreeMap;

use crate::core::types::{Evidence, Finding, Manifest, OutputFormat, Signal, TrendReport};
use serde::Serialize;

pub struct ReportPaths {
    pub evidence_path: PathBuf,
    pub output_path: PathBuf,
    pub manifest_path: PathBuf,
    pub detectors: Vec<String>,
}

pub fn write_evidence_jsonl(
    evidence: &mut Vec<Evidence>,
    path: &Path,
    scope: &Scope,
) -> Result<()> {
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    let mut lines = String::new();
    for ev in evidence.iter() {
        let mut ev = ev.clone();
        if !scope.privacy.store_raw {
            ev.note = None;
            ev.url = None;
            ev.redacted = true;
        }
        lines.push_str(&serde_json::to_string(&ev)?);
        lines.push('\n');
    }
    fs::write(path, lines)?;
    Ok(())
}

pub fn write_manifest(manifest: &Manifest, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, json)?;
    Ok(())
}

pub fn write_signals_output(signals: &[Signal], format: OutputFormat, path: &Path) -> Result<()> {
    let mut sorted = signals.to_vec();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match format {
        OutputFormat::Json => write_json(&sorted, path),
        OutputFormat::Jsonl => write_jsonl(&sorted, path),
        OutputFormat::Markdown => write_markdown(&sorted, path),
        OutputFormat::Sarif => write_sarif(&sorted, path),
        OutputFormat::Csv => write_csv(&sorted, path),
    }
}

pub fn write_report_json(signals: &[Signal], findings: &[Finding], path: &Path) -> Result<()> {
    let bundle = ReportBundle { signals, findings };
    let json = serde_json::to_string_pretty(&bundle)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn write_report_jsonl(signals: &[Signal], findings: &[Finding], path: &Path) -> Result<()> {
    let mut out = String::new();
    for finding in findings {
        let record = ReportRecord::Finding(finding);
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    for signal in signals {
        let record = ReportRecord::Signal(signal);
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

pub fn write_trend_markdown(report: &TrendReport, path: &Path) -> Result<()> {
    let mut out = String::new();
    out.push_str("# BloodyFalcon Trend Report\n\n");
    out.push_str(&format!(
        "- Window: {} to {}\n",
        report.window_start.to_rfc3339(),
        report.window_end.to_rfc3339()
    ));
    out.push('\n');
    if report.summary.is_empty() {
        out.push_str("No activity in this window.\n\n");
    } else {
        out.push_str("## Summary\n");
        for line in &report.summary {
            out.push_str(&format!("- {}\n", line));
        }
        out.push('\n');
    }

    out.push_str("## By Signal Type\n");
    write_trend_section(&mut out, &report.by_signal_type);
    out.push_str("## By Subject\n");
    write_trend_section(&mut out, &report.by_subject);
    out.push_str("## By Dedupe Key\n");
    write_trend_section(&mut out, &report.by_dedupe_key);

    fs::write(path, out)?;
    Ok(())
}

pub fn write_trend_json(report: &TrendReport, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn write_trend_jsonl(report: &TrendReport, path: &Path) -> Result<()> {
    let mut out = String::new();
    let header = serde_json::json!({
        "record_type": "trend_window",
        "window_start": report.window_start,
        "window_end": report.window_end,
    });
    out.push_str(&serde_json::to_string(&header)?);
    out.push('\n');
    for bucket in &report.by_signal_type {
        let record = serde_json::json!({
            "record_type": "by_signal_type",
            "bucket": bucket,
        });
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    for bucket in &report.by_subject {
        let record = serde_json::json!({
            "record_type": "by_subject",
            "bucket": bucket,
        });
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    for bucket in &report.by_dedupe_key {
        let record = serde_json::json!({
            "record_type": "by_dedupe_key",
            "bucket": bucket,
        });
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    for line in &report.summary {
        let record = serde_json::json!({
            "record_type": "summary",
            "text": line,
        });
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

pub fn write_trend_csv(report: &TrendReport, path: &Path) -> Result<()> {
    let mut out = String::new();
    out.push_str(
        "dimension,key,count,prev_count,delta,first_seen,last_seen,first_seen_in_window\n",
    );
    for (dimension, buckets) in [
        ("signal_type", &report.by_signal_type),
        ("subject", &report.by_subject),
        ("dedupe_key", &report.by_dedupe_key),
    ] {
        for bucket in buckets.iter() {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                dimension,
                bucket.key,
                bucket.count,
                bucket.prev_count,
                bucket.delta,
                bucket
                    .first_seen
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "".to_string()),
                bucket
                    .last_seen
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "".to_string()),
                bucket.first_seen_in_window
            ));
        }
    }
    fs::write(path, out)?;
    Ok(())
}

#[derive(Serialize)]
struct ReportBundle<'a> {
    signals: &'a [Signal],
    findings: &'a [Finding],
}

#[derive(Serialize)]
#[serde(tag = "record_type", content = "record")]
enum ReportRecord<'a> {
    Signal(&'a Signal),
    Finding(&'a Finding),
}

pub fn write_markdown_report(signals: &[Signal], findings: &[Finding], path: &Path) -> Result<()> {
    let mut sorted_signals = signals.to_vec();
    sorted_signals.sort_by(|a, b| a.id.cmp(&b.id));
    let mut sorted_findings = findings.to_vec();
    sorted_findings.sort_by(|a, b| a.id.cmp(&b.id));

    let mut out = String::new();
    out.push_str("# BloodyFalcon Report\n\n");
    out.push_str("## Executive Summary\n");
    out.push_str(&format!("- Signals: {}\n", sorted_signals.len()));
    out.push_str(&format!("- Findings: {}\n\n", sorted_findings.len()));

    if sorted_findings.is_empty() {
        out.push_str("No findings.\n\n");
    } else {
        let signal_index = signal_index(&sorted_signals);
        for finding in &sorted_findings {
            out.push_str(&format!("## Finding — {}\n", finding.title));
            out.push_str(&format!("- Disposition: {:?}\n", finding.disposition));
            out.push_str(&format!("- Severity: {:?}\n", finding.severity));
            out.push_str(&format!("- Confidence: {}\n", finding.confidence));
            out.push_str(&format!("- Rationale: {}\n\n", finding.rationale));
            if !finding.policy_gates.is_empty() {
                out.push_str(&format!(
                    "- Policy gates: {}\n",
                    finding.policy_gates.join("; ")
                ));
            }
            if let Some(blocked_by) = &finding.blocked_by {
                out.push_str(&format!("- Blocked by: {}\n", blocked_by));
            }
            if let Some(reason) = &finding.suppression_reason {
                out.push_str(&format!("- Suppression reason: {}\n", reason));
            }
            out.push('\n');

            if matches!(
                finding.disposition,
                crate::core::types::FindingDisposition::Alert
            ) {
                out.push_str("### Why this alert fired\n");
                let rules = trace_entries(&finding.rule_trace, "rule:");
                let adjustments = trace_entries(&finding.rule_trace, "confidence:");
                let notes = trace_entries(&finding.rule_trace, "note:");
                if !rules.is_empty() {
                    out.push_str(&format!("- Rules triggered: {}\n", rules.join(", ")));
                } else {
                    out.push_str("- Rules triggered: none\n");
                }
                if !adjustments.is_empty() {
                    out.push_str(&format!(
                        "- Confidence adjustments: {}\n",
                        adjustments.join(", ")
                    ));
                } else {
                    out.push_str("- Confidence adjustments: none\n");
                }
                out.push_str("- Corroborating signals:\n");
                if finding.signals.is_empty() {
                    out.push_str("  - none\n");
                } else {
                    for sig_id in &finding.signals {
                        if let Some(sig) = signal_index.get(sig_id) {
                            let indicators = sig
                                .indicators
                                .iter()
                                .map(|i| i.0.clone())
                                .collect::<Vec<_>>()
                                .join(", ");
                            out.push_str(&format!(
                                "  - {} ({:?}, {}, {})\n",
                                sig.id, sig.signal_type, sig.subject, indicators
                            ));
                        } else {
                            out.push_str(&format!("  - {}\n", sig_id));
                        }
                    }
                }
                if !notes.is_empty() {
                    out.push_str(&format!("- Notes: {}\n", notes.join(", ")));
                }
                out.push('\n');
            }
        }
    }

    out.push_str("## Signals\n\n");
    if sorted_signals.is_empty() {
        out.push_str("No signals.\n");
    } else {
        for sig in &sorted_signals {
            out.push_str(&format!("### {:?} — {}\n", sig.signal_type, sig.subject));
            out.push_str(&format!("- Severity: {:?}\n", sig.severity));
            out.push_str(&format!("- Confidence: {}\n", sig.confidence));
            out.push_str(&format!("- Source: {}\n", sig.source));
            out.push_str(&format!("- Evidence: {}\n", sig.evidence_ref));
            out.push_str(&format!("- Rationale: {}\n", sig.rationale));
            if !sig.recommended_actions.is_empty() {
                out.push_str("- Recommended Actions:\n");
                for action in &sig.recommended_actions {
                    out.push_str(&format!("  - {}\n", action));
                }
            }
            out.push('\n');
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, out)?;
    Ok(())
}

fn write_json(signals: &[Signal], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(signals)?;
    fs::write(path, json)?;
    Ok(())
}

fn write_jsonl(signals: &[Signal], path: &Path) -> Result<()> {
    let mut out = String::new();
    for sig in signals {
        out.push_str(&serde_json::to_string(sig)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

fn write_markdown(signals: &[Signal], path: &Path) -> Result<()> {
    let mut out = String::new();
    out.push_str("# BloodyFalcon Report\n\n");
    if signals.is_empty() {
        out.push_str("No signals.\n");
    }
    for sig in signals {
        out.push_str(&format!("## {:?} — {}\n", sig.signal_type, sig.subject));
        out.push_str(&format!("- Severity: {:?}\n", sig.severity));
        out.push_str(&format!("- Confidence: {}\n", sig.confidence));
        out.push_str(&format!("- Source: {}\n", sig.source));
        out.push_str(&format!("- Evidence: {}\n", sig.evidence_ref));
        out.push_str(&format!("- Rationale: {}\n", sig.rationale));
        if !sig.recommended_actions.is_empty() {
            out.push_str("- Recommended Actions:\n");
            for action in &sig.recommended_actions {
                out.push_str(&format!("  - {}\n", action));
            }
        }
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

fn write_sarif(signals: &[Signal], path: &Path) -> Result<()> {
    let results: Vec<serde_json::Value> = signals
        .iter()
        .map(|s| {
            serde_json::json!({
                "ruleId": format!("{:?}", s.signal_type),
                "level": sarif_level(&s.severity),
                "message": {"text": s.rationale},
                "properties": {
                    "subject": s.subject,
                    "confidence": s.confidence,
                    "evidence": s.evidence_ref,
                }
            })
        })
        .collect();

    let log = serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "bloodyfalcon", "version": "0.2.0"}},
            "results": results
        }]
    });
    fs::write(path, serde_json::to_string_pretty(&log)?)?;
    Ok(())
}

fn write_csv(signals: &[Signal], path: &Path) -> Result<()> {
    let mut out = String::new();
    out.push_str("id,signal_type,subject,source,severity,confidence,evidence\n");
    for s in signals {
        out.push_str(&format!(
            "{},{:?},{},{},{:?},{},{}\n",
            s.id, s.signal_type, s.subject, s.source, s.severity, s.confidence, s.evidence_ref
        ));
    }
    fs::write(path, out)?;
    Ok(())
}

fn sarif_level(sev: &crate::core::types::Severity) -> &'static str {
    match sev {
        crate::core::types::Severity::Low => "note",
        crate::core::types::Severity::Medium => "warning",
        crate::core::types::Severity::High | crate::core::types::Severity::Critical => "error",
    }
}

fn write_trend_section(out: &mut String, buckets: &[crate::core::types::TrendBucket]) {
    if buckets.is_empty() {
        out.push_str("- No activity.\n\n");
        return;
    }
    for bucket in buckets {
        out.push_str(&format!(
            "- {}: count={}, prev={}, delta={}, first_seen_in_window={}\n",
            bucket.key, bucket.count, bucket.prev_count, bucket.delta, bucket.first_seen_in_window
        ));
    }
    out.push('\n');
}

fn signal_index(signals: &[Signal]) -> BTreeMap<String, Signal> {
    let mut map = BTreeMap::new();
    for sig in signals {
        map.insert(sig.id.clone(), sig.clone());
    }
    map
}

fn trace_entries(trace: &[String], prefix: &str) -> Vec<String> {
    trace
        .iter()
        .filter_map(|entry| entry.strip_prefix(prefix).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}
