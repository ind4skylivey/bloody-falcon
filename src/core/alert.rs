use reqwest::Client;

use crate::core::error::FalconError;
use crate::core::signal::{Severity, Signal};

pub async fn send_webhook_alert(
    client: &Client,
    webhook_url: &str,
    signals: &[Signal],
) -> Result<(), FalconError> {
    if signals.is_empty() {
        return Ok(());
    }
    let text = format_alert_text(signals);
    client
        .post(webhook_url)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await
        .map_err(FalconError::from)?;
    Ok(())
}

fn format_alert_text(signals: &[Signal]) -> String {
    let mut lines = vec!["🦅 Bloody-F4lcon alert".to_string()];
    for sig in signals {
        lines.push(format!(
            "- {:?} | {} | severity={:?} confidence={} tags={}",
            sig.signal_type,
            sig.subject,
            sig.severity,
            sig.confidence,
            sig.tags.join(",")
        ));
        if let Some(ev) = sig.evidence.first() {
            if let Some(url) = &ev.url {
                lines.push(format!("  evidence: {} ({})", url, ev.source));
            }
        }
    }
    lines.join("\n")
}

pub fn meets_threshold(sig: &Signal, severity_floor: &Severity, confidence_floor: u8) -> bool {
    severity_value(&sig.severity) >= severity_value(severity_floor)
        && sig.confidence >= confidence_floor
}

fn severity_value(sev: &Severity) -> u8 {
    match sev {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
    }
}
