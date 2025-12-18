use crate::core::scope::Scope;
use crate::core::types::{Finding, FindingDisposition, Severity};

pub fn escalate_findings(findings: Vec<Finding>, scope: &Scope) -> Vec<Finding> {
    let min_conf = scope.policy.min_confidence_alert;
    let min_sev = &scope.policy.min_severity_alert;

    let mut out = Vec::new();
    for mut finding in findings {
        let sev_ok = severity_rank(&finding.severity) >= severity_rank(min_sev);
        let conf_ok = finding.confidence >= min_conf;

        let mut gates = Vec::new();
        gates.push(format!(
            "min_severity_alert={:?} (actual={:?})",
            min_sev, finding.severity
        ));
        gates.push(format!(
            "min_confidence_alert={} (actual={})",
            min_conf, finding.confidence
        ));

        finding.policy_gates = gates;

        if let Some(reason) = finding.suppression_reason.clone() {
            finding.disposition = FindingDisposition::Suppressed;
            finding.blocked_by = Some(format!("suppressed: {}", reason));
            out.push(finding);
            continue;
        }

        if finding_has_policy_flag(&finding, "prefer_digest:old_domain") {
            finding.disposition = FindingDisposition::Digest;
            finding.blocked_by = Some("policy: typosquat.old_domain_days".to_string());
            out.push(finding);
            continue;
        }

        if sev_ok && conf_ok {
            finding.disposition = FindingDisposition::Alert;
            finding.blocked_by = None;
        } else if finding.severity == Severity::Medium || finding.severity == Severity::High {
            finding.disposition = FindingDisposition::Investigate;
            finding.blocked_by = Some(blocked_by(sev_ok, conf_ok));
        } else {
            finding.disposition = FindingDisposition::Digest;
            finding.blocked_by = Some(blocked_by(sev_ok, conf_ok));
        }

        out.push(finding);
    }

    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn severity_rank(sev: &Severity) -> u8 {
    match sev {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn blocked_by(sev_ok: bool, conf_ok: bool) -> String {
    match (sev_ok, conf_ok) {
        (false, false) => "policy: severity and confidence below thresholds".to_string(),
        (false, true) => "policy: severity below threshold".to_string(),
        (true, false) => "policy: confidence below threshold".to_string(),
        (true, true) => "policy: none".to_string(),
    }
}

fn finding_has_policy_flag(finding: &Finding, flag: &str) -> bool {
    let needle = format!("policy_flag:{}", flag);
    finding
        .rule_trace
        .iter()
        .any(|entry| entry.trim() == needle)
}
