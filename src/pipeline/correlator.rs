use std::collections::BTreeMap;

use crate::core::hash::sha256_hex;
use crate::core::types::{Finding, FindingDisposition, Indicator, Severity, Signal, SignalType};

pub fn correlate_signals(signals: &[Signal]) -> Vec<Finding> {
    let mut by_subject: BTreeMap<String, Vec<&Signal>> = BTreeMap::new();
    for sig in signals {
        by_subject.entry(sig.subject.clone()).or_default().push(sig);
    }

    let mut findings = Vec::new();
    for (subject, sigs) in by_subject {
        let mut typos = Vec::new();
        let mut new_certs = Vec::new();
        let mut impersonations = Vec::new();
        let mut mention_spikes = Vec::new();
        let mut landing_signals = Vec::new();

        for sig in &sigs {
            match sig.signal_type {
                SignalType::TyposquatDomain => typos.push(*sig),
                SignalType::NewCert => new_certs.push(*sig),
                SignalType::Impersonation => impersonations.push(*sig),
                SignalType::MentionSpike => mention_spikes.push(*sig),
                _ => {}
            }
            if has_landing_indicator(&sig.indicators) {
                landing_signals.push(*sig);
            }
        }

        let subject_corroborated = has_corroboration(&sigs);
        let eligible_typos: Vec<&Signal> = typos
            .iter()
            .copied()
            .filter(|sig| {
                let candidate = sig
                    .indicators
                    .first()
                    .map(|i| i.0.clone())
                    .unwrap_or_default();
                if candidate.is_empty() {
                    return false;
                }
                let generic_only = is_generic_typosquat(&subject, &candidate);
                !generic_only || subject_corroborated
            })
            .collect();

        if !eligible_typos.is_empty() && !new_certs.is_empty() && !landing_signals.is_empty() {
            let mut contributing = Vec::new();
            contributing.extend(eligible_typos.iter().copied());
            contributing.extend(new_certs.iter().copied());
            contributing.extend(landing_signals.iter().copied());
            let confidence = add_confidence(max_confidence(&contributing), 25);
            let mut rule_trace = vec![
                "rule:typosquat_newcert_landing".to_string(),
                "confidence:+25 (typosquat + new cert + landing similarity)".to_string(),
                "severity:high".to_string(),
            ];
            append_policy_flags(&mut rule_trace, &contributing);
            findings.push(Finding {
                id: finding_id("typosquat_newcert_landing", &contributing),
                title: format!("Potential impersonation infrastructure for {}", subject),
                signals: sorted_signal_ids(&contributing),
                confidence,
                severity: Severity::High,
                rationale:
                    "Typosquat domain observed alongside new certificate and landing similarity."
                        .to_string(),
                rule_trace,
                disposition: FindingDisposition::Digest,
                policy_gates: vec![],
                blocked_by: None,
                suppression_reason: aggregate_suppression_reason(
                    &contributing,
                    subject_corroborated,
                ),
            });
        }

        if !impersonations.is_empty() && !mention_spikes.is_empty() {
            let mut contributing = Vec::new();
            contributing.extend(impersonations.iter().copied());
            contributing.extend(mention_spikes.iter().copied());
            let confidence = add_confidence(max_confidence(&contributing), 15);
            let mut rule_trace = vec![
                "rule:impersonation_mention_spike".to_string(),
                "confidence:+15 (impersonation + mention spike)".to_string(),
                "severity:medium".to_string(),
            ];
            append_policy_flags(&mut rule_trace, &contributing);
            findings.push(Finding {
                id: finding_id("impersonation_mention_spike", &contributing),
                title: format!("Impersonation signals with mention spike for {}", subject),
                signals: sorted_signal_ids(&contributing),
                confidence,
                severity: Severity::Medium,
                rationale: "Impersonation indicators corroborated by mention spike.".to_string(),
                rule_trace,
                disposition: FindingDisposition::Digest,
                policy_gates: vec![],
                blocked_by: None,
                suppression_reason: aggregate_suppression_reason(
                    &contributing,
                    subject_corroborated,
                ),
            });
        }
    }

    findings.sort_by(|a, b| a.id.cmp(&b.id));
    findings
}

fn finding_id(rule: &str, signals: &[&Signal]) -> String {
    let mut ids: Vec<String> = signals.iter().map(|s| s.id.clone()).collect();
    ids.sort();
    let payload = format!("{}|{}", rule, ids.join(","));
    format!("finding_{}", sha256_hex(payload.as_bytes()))
}

fn sorted_signal_ids(signals: &[&Signal]) -> Vec<String> {
    let mut ids: Vec<String> = signals.iter().map(|s| s.id.clone()).collect();
    ids.sort();
    ids
}

fn max_confidence(signals: &[&Signal]) -> u8 {
    signals.iter().map(|s| s.confidence).max().unwrap_or(0)
}

fn add_confidence(base: u8, bonus: u8) -> u8 {
    base.saturating_add(bonus).min(100)
}

fn has_landing_indicator(indicators: &[Indicator]) -> bool {
    indicators.iter().any(|ind| {
        let v = ind.0.to_lowercase();
        v.contains("landing_similarity") || v.contains("favicon_similarity")
    })
}

fn has_corroboration(signals: &[&Signal]) -> bool {
    for sig in signals {
        if sig.signal_type == SignalType::NewCert {
            return true;
        }
        if has_ct_indicator(&sig.indicators) || has_young_domain(&sig.indicators) {
            return true;
        }
    }
    false
}

fn has_ct_indicator(indicators: &[Indicator]) -> bool {
    indicators.iter().any(|ind| {
        let v = ind.0.to_lowercase();
        v.contains("ct_cert") || v.contains("ct_log") || v.contains("new_cert")
    })
}

fn has_young_domain(indicators: &[Indicator]) -> bool {
    indicators.iter().any(|ind| {
        let v = ind.0.to_lowercase();
        if let Some(num) = v.strip_prefix("rdap_age_days=") {
            if let Ok(days) = num.parse::<i64>() {
                return days < 30;
            }
        }
        false
    })
}

fn is_generic_typosquat(subject: &str, candidate: &str) -> bool {
    let generic = ["login", "secure", "support", "billing", "account", "verify"];
    let base = sld_tokens(subject);
    let mut cand_tokens = sld_tokens(candidate);
    cand_tokens.retain(|t| !base.contains(t));
    if cand_tokens.is_empty() {
        return false;
    }
    cand_tokens.iter().all(|t| generic.contains(&t.as_str()))
}

fn aggregate_suppression_reason(signals: &[&Signal], subject_corroborated: bool) -> Option<String> {
    let mut reasons: Vec<String> = signals
        .iter()
        .filter_map(|s| s.suppression_reason.clone())
        .collect();
    if subject_corroborated {
        reasons.retain(|r| !r.contains("generic-token"));
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

fn append_policy_flags(rule_trace: &mut Vec<String>, signals: &[&Signal]) {
    let mut flags: Vec<String> = signals
        .iter()
        .flat_map(|s| s.policy_flags.iter().cloned())
        .collect();
    flags.sort();
    flags.dedup();
    for flag in flags {
        rule_trace.push(format!("policy_flag:{}", flag));
    }
}

fn sld_tokens(domain: &str) -> Vec<String> {
    let sld = domain.split('.').next().unwrap_or(domain);
    sld.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}
