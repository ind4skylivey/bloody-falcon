use crate::core::scope::Scope;
use crate::core::time::now_utc;
use crate::core::types::{Indicator, Severity, Signal, SignalType};

pub fn score_signals(signals: &mut [Signal], scope: &Scope) {
    for sig in signals.iter_mut() {
        if sig.confidence == 0 {
            sig.confidence = default_confidence(&sig.signal_type);
        }
        if matches!(
            sig.severity,
            Severity::Low | Severity::Medium | Severity::High | Severity::Critical
        ) {
            // keep if already set
        } else {
            sig.severity = default_severity(&sig.signal_type);
        }

        apply_negative_keyword_filter(sig, scope);
        apply_temporal_decay(sig);
        apply_typosquat_tuning(sig, scope);
    }
}

fn default_confidence(signal_type: &SignalType) -> u8 {
    match signal_type {
        SignalType::TyposquatDomain => 60,
        SignalType::ExposureCode => 70,
        SignalType::ExposurePaste => 70,
        SignalType::Impersonation => 55,
        SignalType::NewCert => 50,
        SignalType::MentionSpike => 40,
        SignalType::ThreatFeedMatch => 75,
    }
}

fn default_severity(signal_type: &SignalType) -> Severity {
    match signal_type {
        SignalType::ExposurePaste => Severity::High,
        SignalType::ExposureCode => Severity::Medium,
        SignalType::TyposquatDomain => Severity::Medium,
        SignalType::NewCert => Severity::Medium,
        SignalType::Impersonation => Severity::Medium,
        SignalType::MentionSpike => Severity::Low,
        SignalType::ThreatFeedMatch => Severity::High,
    }
}

fn apply_typosquat_tuning(sig: &mut Signal, scope: &Scope) {
    if sig.signal_type != SignalType::TyposquatDomain {
        return;
    }
    let candidate = sig
        .indicators
        .first()
        .map(|i| i.0.clone())
        .unwrap_or_default();
    if candidate.is_empty() {
        return;
    }

    let generic_only = is_generic_typosquat(&sig.subject, &candidate, scope);
    let corroborated = has_corroboration(&sig.indicators);

    if generic_only && !corroborated {
        if sig.confidence > 60 {
            sig.confidence = 60;
        }
        if matches!(sig.severity, Severity::High | Severity::Critical) {
            sig.severity = Severity::Medium;
        }
        let note = "suppressed: generic-token typosquat without corroboration; confidence capped at 60; severity capped at Medium; digest-only";
        if !sig.rationale.contains(note) {
            sig.rationale = format!("{} | {}", sig.rationale, note);
        }
        sig.suppression_reason = Some("generic-token typosquat without corroboration".to_string());
        if !sig
            .policy_flags
            .iter()
            .any(|f| f == "suppressed:generic_token")
        {
            sig.policy_flags
                .push("suppressed:generic_token".to_string());
        }
    }

    if let Some(age_days) = indicator_age_days(&sig.indicators) {
        let max_days = scope.policy.typosquat.old_domain_days as i64;
        if age_days > max_days {
            if sig.confidence > 50 {
                sig.confidence = 50;
            }
            if matches!(sig.severity, Severity::High | Severity::Critical) {
                sig.severity = Severity::Medium;
            }
            let note = format!(
                "policy: domain age {}d exceeds {}d; confidence capped; prefer digest",
                age_days, max_days
            );
            if !sig.rationale.contains(&note) {
                sig.rationale = format!("{} | {}", sig.rationale, note);
            }
            if !sig
                .policy_flags
                .iter()
                .any(|f| f == "prefer_digest:old_domain")
            {
                sig.policy_flags
                    .push("prefer_digest:old_domain".to_string());
            }
        }
    }
}

fn is_generic_typosquat(subject: &str, candidate: &str, scope: &Scope) -> bool {
    let generic = scope
        .policy
        .typosquat
        .generic_tokens
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>();
    let base = sld_tokens(subject);
    let mut cand_tokens = sld_tokens(candidate);
    cand_tokens.retain(|t| !base.contains(t));
    if cand_tokens.is_empty() {
        return false;
    }
    cand_tokens.iter().all(|t| generic.contains(&t.as_str()))
}

fn sld_tokens(domain: &str) -> Vec<String> {
    let sld = domain.split('.').next().unwrap_or(domain);
    sld.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

fn has_corroboration(indicators: &[Indicator]) -> bool {
    for ind in indicators {
        let v = ind.0.to_lowercase();
        if let Some(num) = v.strip_prefix("rdap_age_days=") {
            if let Ok(days) = num.parse::<i64>() {
                if days < 30 {
                    return true;
                }
            }
        }
        if v.contains("ct_cert") || v.contains("ct_log") || v.contains("new_cert") {
            return true;
        }
        if v.contains("landing_similarity") || v.contains("favicon_similarity") {
            return true;
        }
    }
    false
}

fn indicator_age_days(indicators: &[Indicator]) -> Option<i64> {
    for ind in indicators {
        let v = ind.0.to_lowercase();
        if let Some(num) = v.strip_prefix("rdap_age_days=") {
            if let Ok(days) = num.parse::<i64>() {
                return Some(days);
            }
        }
    }
    None
}

fn apply_negative_keyword_filter(sig: &mut Signal, scope: &Scope) {
    if scope.negative_keywords.is_empty() {
        return;
    }
    let hay = format!(
        "{} {} {}",
        sig.subject,
        sig.rationale,
        sig.indicators
            .iter()
            .map(|i| i.0.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase();
    for keyword in &scope.negative_keywords {
        if keyword.trim().is_empty() {
            continue;
        }
        let needle = keyword.to_lowercase();
        if hay.contains(&needle) {
            sig.confidence = sig.confidence.min(20);
            sig.severity = Severity::Low;
            let note = format!("suppressed: negative keyword match '{}'", keyword);
            if !sig.rationale.contains(&note) {
                sig.rationale = format!("{} | {}", sig.rationale, note);
            }
            sig.suppression_reason = Some(format!("negative keyword match: {}", keyword));
            if !sig
                .policy_flags
                .iter()
                .any(|f| f == "suppressed:negative_keyword")
            {
                sig.policy_flags
                    .push("suppressed:negative_keyword".to_string());
            }
            break;
        }
    }
}

fn apply_temporal_decay(sig: &mut Signal) {
    let now = now_utc();
    let age = now.signed_duration_since(sig.timestamp);
    if age.num_days() <= 30 {
        return;
    }
    let decayed = sig.confidence.saturating_sub(10);
    if decayed < sig.confidence {
        sig.confidence = decayed.max(20);
        let note = format!("policy: temporal decay applied ({}d)", age.num_days());
        if !sig.rationale.contains(&note) {
            sig.rationale = format!("{} | {}", sig.rationale, note);
        }
        if !sig.policy_flags.iter().any(|f| f == "decay:temporal") {
            sig.policy_flags.push("decay:temporal".to_string());
        }
    }
}
