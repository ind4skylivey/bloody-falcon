use anyhow::Result;

use crate::core::scope::Scope;
use crate::core::types::{Indicator, Severity, Signal, SignalType};
use crate::detectors::Detector;
use crate::pipeline::collector::RunCtx;
use crate::sources::SourceKind;

pub struct TyposquatDetector;

impl Detector for TyposquatDetector {
    fn name(&self) -> &'static str {
        "typosquat"
    }

    fn sources(&self) -> Vec<SourceKind> {
        vec![SourceKind::Offline]
    }

    fn run(&self, scope: &Scope, ctx: &RunCtx) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        for domain in scope.domains.iter() {
            for candidate in permutations(domain) {
                let sig = Signal {
                    id: String::new(),
                    signal_type: SignalType::TyposquatDomain,
                    subject: domain.clone(),
                    source: "typosquat".to_string(),
                    evidence_ref: String::new(),
                    timestamp: ctx.window.start,
                    indicators: vec![Indicator(candidate)],
                    confidence: 0,
                    severity: Severity::Medium,
                    rationale: "Generated typosquat candidate".to_string(),
                    recommended_actions: vec![
                        "Review domain registration and hosting".to_string(),
                        "Consider takedown if abusive".to_string(),
                    ],
                    dedupe_key: String::new(),
                    tags: vec!["typosquat".to_string()],
                    suppression_reason: None,
                    policy_flags: vec![],
                };
                signals.push(sig);
            }
        }
        Ok(signals)
    }
}

fn permutations(domain: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((sld, tld)) = domain.rsplit_once('.') {
        out.push(format!("{}-secure.{}", sld, tld));
        out.push(format!("{}-login.{}", sld, tld));
        out.push(format!("{}-support.{}", sld, tld));
        out.push(format!("{}-billing.{}", sld, tld));
        out.push(format!("secure-{}.{}", sld, tld));
        out.push(format!("login-{}.{}", sld, tld));
    } else {
        out.push(format!("{}-secure", domain));
        out.push(format!("{}-login", domain));
    }
    out.sort();
    out.dedup();
    out
}
