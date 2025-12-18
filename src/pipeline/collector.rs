use std::path::Path;

use anyhow::Result;

use crate::core::scope::Scope;
use crate::core::time::RunWindow;
use crate::core::types::Signal;
use crate::detectors::typosquat::TyposquatDetector;
use crate::detectors::Detector;
use crate::sources::SourceKind;

#[derive(Clone, Debug)]
pub struct RunCtx {
    pub no_network: bool,
    pub window: RunWindow,
}

pub struct CollectResult {
    pub signals: Vec<Signal>,
    pub detectors: Vec<String>,
}

pub fn collect_signals(
    scope: &Scope,
    ctx: &RunCtx,
    detectors_filter: Option<Vec<String>>,
) -> Result<CollectResult> {
    let mut signals = Vec::new();
    let mut detectors_used = Vec::new();
    let filter = detectors_filter
        .unwrap_or_else(|| scope.allowed_detectors.clone())
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>();

    let typosquat = TyposquatDetector;
    if filter.contains(&typosquat.name().to_string()) {
        enforce_no_network(ctx, &typosquat)?;
        detectors_used.push(typosquat.name().to_string());
        signals.extend(typosquat.run(scope, ctx)?);
    }

    Ok(CollectResult {
        signals,
        detectors: detectors_used,
    })
}

fn enforce_no_network<D: Detector>(ctx: &RunCtx, detector: &D) -> Result<()> {
    if ctx.no_network {
        let uses_network = detector.sources().iter().any(|s| *s != SourceKind::Offline);
        if uses_network {
            return Err(anyhow::anyhow!(
                "no-network mode forbids detector: {}",
                detector.name()
            ));
        }
    }
    Ok(())
}

pub fn load_fixture_signals(path: &Path) -> Result<Vec<Signal>> {
    let data = std::fs::read_to_string(path)?;
    let mut signals = Vec::new();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let sig: Signal = serde_json::from_str(line)?;
        signals.push(sig);
    }
    Ok(signals)
}
