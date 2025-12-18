use anyhow::Result;

use crate::core::hash::{dedupe_key, stable_signal_id};
use crate::core::scope::Scope;
use crate::core::time::now_utc;
use crate::core::types::{Evidence, Indicator, Signal};

pub fn normalize_signals(
    mut signals: Vec<Signal>,
    scope: &Scope,
) -> Result<(Vec<Signal>, Vec<Evidence>)> {
    let mut evidence = Vec::new();
    for sig in signals.iter_mut() {
        normalize_signal(sig, scope);
        let ev_id = sig.evidence_ref.clone();
        let ev = Evidence {
            id: ev_id.clone(),
            source: sig.source.clone(),
            observed_at: sig.timestamp,
            url: None,
            note: None,
            redacted: !scope.privacy.store_raw,
        };
        evidence.push(ev);
    }

    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    signals.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((signals, evidence))
}

fn normalize_signal(sig: &mut Signal, scope: &Scope) {
    sig.indicators.sort_by(|a, b| a.0.cmp(&b.0));
    if sig.evidence_ref.is_empty() {
        sig.evidence_ref = format!(
            "ev_{}",
            stable_signal_id(&sig.signal_type, &sig.subject, "", &sig.indicators)
        );
    }
    if sig.id.is_empty() {
        sig.id = stable_signal_id(
            &sig.signal_type,
            &sig.subject,
            &sig.evidence_ref,
            &sig.indicators,
        );
    }
    if sig.dedupe_key.is_empty() {
        sig.dedupe_key = dedupe_key(&sig.signal_type, &sig.subject, &sig.indicators);
    }
    if sig.timestamp.timestamp() == 0 {
        sig.timestamp = now_utc();
    }

    if !scope.privacy.store_raw && !scope.privacy.redact_patterns.is_empty() {
        for ind in sig.indicators.iter_mut() {
            ind.0 = redact_text(&ind.0, scope);
        }
        sig.rationale = redact_text(&sig.rationale, scope);
        sig.recommended_actions = sig
            .recommended_actions
            .iter()
            .map(|t| redact_text(t, scope))
            .collect();
    }
}

fn redact_text(input: &str, scope: &Scope) -> String {
    let mut out = input.to_string();
    for re in scope.privacy.redact_patterns.iter() {
        out = re.replace_all(&out, "[REDACTED]").to_string();
    }
    out
}

pub fn indicators_to_strings(indicators: &[Indicator]) -> Vec<String> {
    indicators.iter().map(|i| i.0.clone()).collect()
}
