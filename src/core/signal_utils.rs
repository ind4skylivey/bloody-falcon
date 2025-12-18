use chrono::Utc;

use crate::core::{
    engine::Engine,
    signal::{Evidence, Severity, Signal, SignalType},
};

/// Convert username recon results into normalized signals.
pub fn recon_to_signals(
    username: &str,
    recon: &crate::core::engine::ReconResult,
    engine: &Engine,
    demo_mode: bool,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    for platform in recon.platforms.iter() {
        let evidence_url = engine.provider_url(platform, username);
        let evidence = Evidence {
            source: platform.clone(),
            url: evidence_url,
            observed_at: Utc::now(),
            note: Some("Account exists; verify ownership".to_string()),
        };
        signals.push(build_signal(
            SignalType::Impersonation,
            username,
            vec![evidence],
            70,
            Severity::Medium,
            vec!["impersonation".into(), "brand-abuse".into()],
            "Validate if this account is legitimate; report or claim if not.",
        ));
    }

    for platform in recon.restricted.iter() {
        let evidence = Evidence {
            source: platform.clone(),
            url: engine.provider_url(platform, username),
            observed_at: Utc::now(),
            note: Some("Access restricted; could indicate geofence or auth wall.".into()),
        };
        signals.push(build_signal(
            SignalType::Impersonation,
            username,
            vec![evidence],
            50,
            Severity::Medium,
            vec!["restricted".into()],
            "Review access restrictions; consider authenticated check.",
        ));
    }

    if demo_mode && signals.is_empty() {
        let evidence = Evidence {
            source: "demo".to_string(),
            url: None,
            observed_at: Utc::now(),
            note: Some("Demo mode placeholder signal".into()),
        };
        signals.push(build_signal(
            SignalType::MentionSpike,
            username,
            vec![evidence],
            30,
            Severity::Low,
            vec!["demo".into()],
            "Run with --scope to generate real signals.",
        ));
    }

    signals
}

pub fn build_signal(
    signal_type: SignalType,
    subject: &str,
    evidence: Vec<Evidence>,
    confidence: u8,
    severity: Severity,
    tags: Vec<String>,
    recommended_action: &str,
) -> Signal {
    let mut parts = vec![format!("{:?}", signal_type), subject.to_string()];
    for ev in &evidence {
        parts.push(ev.source.clone());
        if let Some(url) = &ev.url {
            parts.push(url.clone());
        }
    }
    let fingerprint = parts.join("|");
    Signal::new(
        signal_type,
        subject,
        evidence,
        confidence,
        severity,
        tags,
        recommended_action,
        fingerprint,
    )
}

pub fn allows(scope: &crate::core::scope::ClientScope, source: &str) -> bool {
    scope.allowed_sources.is_empty()
        || scope
            .allowed_sources
            .iter()
            .any(|s| s.eq_ignore_ascii_case(source))
}

pub fn parse_severity(value: &str) -> Option<Severity> {
    match value.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        _ => None,
    }
}
