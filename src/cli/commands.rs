use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::cli::config::{
    config_hash, ensure_output_dir, load_scope_from_config, resolve_config, resolve_output_file,
    RunConfig,
};
use crate::cli::flags::{Cli, Command};
use crate::core::hash::{hash_file, sha256_hex, stable_run_id};
use crate::core::scope::Scope;
use crate::core::store::Store;
use crate::core::time::{parse_window, run_window};
use crate::core::types::{Manifest, Signal};
use crate::pipeline::collector::{collect_signals, load_fixture_signals, RunCtx};
use crate::pipeline::correlator::correlate_signals;
use crate::pipeline::escalator::escalate_findings;
use crate::pipeline::normalizer::normalize_signals;
use crate::pipeline::reporter::{
    write_evidence_jsonl, write_manifest, write_signals_output, ReportPaths,
};
use crate::pipeline::scorer::score_signals;
use crate::ui::tui::run_tui;

pub fn run(cli: Cli) -> Result<()> {
    let cfg = resolve_config(&cli)?;
    let mut scope = load_scope_from_config(&cfg)?;
    if cfg.demo_safe {
        scope = scope.sanitize_for_demo();
    }
    scope.validate(cfg.demo_safe)?;
    enforce_scope_filters(&cfg, &scope)?;

    match cli.command {
        Command::Scan => run_scan(&cfg, &scope),
        Command::Replay { fixture, .. } => run_replay(&cfg, &scope, &fixture),
        Command::Report { .. } => run_report(&cfg, &scope),
        Command::Trend { .. } => run_trend(&cfg, &scope),
        Command::Tui { .. } => run_tui_cmd(&cfg, &scope),
    }
}

fn enforce_scope_filters(cfg: &RunConfig, scope: &Scope) -> Result<()> {
    if !cfg.demo_safe && scope.allowed_detectors.is_empty() {
        return Err(anyhow!("scope must include allowed_detectors"));
    }
    if !cfg.demo_safe && scope.allowed_sources.is_empty() {
        return Err(anyhow!("scope must include allowed_sources"));
    }

    if cfg.demo_safe {
        let safe_detectors = ["typosquat"];
        let safe_sources = ["fixture", "offline"];
        if let Some(detectors) = &cfg.detectors {
            for d in detectors {
                if !safe_detectors.iter().any(|s| s.eq_ignore_ascii_case(d)) {
                    return Err(anyhow!("detector not allowed in demo-safe: {}", d));
                }
            }
        }
        if let Some(sources) = &cfg.sources {
            for s in sources {
                if !safe_sources.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                    return Err(anyhow!("source not allowed in demo-safe: {}", s));
                }
            }
        }
    }

    if let Some(detectors) = &cfg.detectors {
        for d in detectors {
            if !scope
                .allowed_detectors
                .iter()
                .any(|s| s.eq_ignore_ascii_case(d))
            {
                return Err(anyhow!("detector not allowed by scope: {}", d));
            }
        }
    }
    if let Some(sources) = &cfg.sources {
        for s in sources {
            if !scope
                .allowed_sources
                .iter()
                .any(|x| x.eq_ignore_ascii_case(s))
            {
                return Err(anyhow!("source not allowed by scope: {}", s));
            }
        }
    }
    Ok(())
}

fn run_scan(cfg: &RunConfig, scope: &Scope) -> Result<()> {
    let window = run_window();
    let ctx = RunCtx {
        no_network: cfg.no_network,
        window: window.clone(),
    };

    let collection = collect_signals(scope, &ctx, cfg.detectors.clone())?;
    let (mut signals, mut evidence) = normalize_signals(collection.signals, scope)?;
    score_signals(&mut signals, scope);
    let findings = correlate_signals(&signals);
    let findings = escalate_findings(findings, scope);

    let report_paths = write_outputs(cfg, scope, &signals, &mut evidence, &collection.detectors)?;
    persist_run(&report_paths, &signals, &findings, scope, cfg, &window)?;
    Ok(())
}

fn run_replay(cfg: &RunConfig, scope: &Scope, fixture: &Path) -> Result<()> {
    run_replay_with_config(cfg, scope, fixture).map(|_| ())
}

pub fn run_replay_with_config(cfg: &RunConfig, scope: &Scope, fixture: &Path) -> Result<Manifest> {
    let window = run_window();
    let signals = load_fixture_signals(fixture)?;
    let (mut signals, mut evidence) = normalize_signals(signals, scope)?;
    score_signals(&mut signals, scope);
    let findings = correlate_signals(&signals);
    let findings = escalate_findings(findings, scope);

    let report_paths = write_outputs(cfg, scope, &signals, &mut evidence, &["replay".into()])?;
    let manifest = persist_run(&report_paths, &signals, &findings, scope, cfg, &window)?;
    Ok(manifest)
}

fn run_report(cfg: &RunConfig, _scope: &Scope) -> Result<()> {
    let db_path = Store::default_path();
    let store = Store::new(&db_path)?;
    let mut signals = store.latest_signals()?;
    let findings = store.latest_findings()?;
    if signals.is_empty() {
        signals = load_signals_fallback(&cfg.output)?;
    }
    if signals.is_empty() {
        return Err(anyhow!("no stored signals available"));
    }

    let output_path = resolve_output_file(&cfg.output, cfg.format, "report");
    if let Some(parent) = output_path.parent() {
        ensure_output_dir(parent)?;
    }

    match cfg.format {
        crate::core::types::OutputFormat::Markdown => {
            crate::pipeline::reporter::write_markdown_report(&signals, &findings, &output_path)?;
        }
        crate::core::types::OutputFormat::Json => {
            crate::pipeline::reporter::write_report_json(&signals, &findings, &output_path)?;
        }
        crate::core::types::OutputFormat::Jsonl => {
            crate::pipeline::reporter::write_report_jsonl(&signals, &findings, &output_path)?;
        }
        _ => {
            write_signals_output(&signals, cfg.format, &output_path)?;
        }
    }
    Ok(())
}

fn run_trend(cfg: &RunConfig, _scope: &Scope) -> Result<()> {
    let window = cfg
        .trend_window
        .clone()
        .ok_or_else(|| anyhow!("trend requires --window"))?;
    let duration = parse_window(&window)?;

    let db_path = Store::default_path();
    let store = Store::new(&db_path)?;
    let report = store.trend_report(duration)?;

    let output_path = resolve_output_file(&cfg.output, cfg.format, "trend");
    if let Some(parent) = output_path.parent() {
        ensure_output_dir(parent)?;
    }

    match cfg.format {
        crate::core::types::OutputFormat::Markdown => {
            crate::pipeline::reporter::write_trend_markdown(&report, &output_path)?;
        }
        crate::core::types::OutputFormat::Json => {
            crate::pipeline::reporter::write_trend_json(&report, &output_path)?;
        }
        crate::core::types::OutputFormat::Jsonl => {
            crate::pipeline::reporter::write_trend_jsonl(&report, &output_path)?;
        }
        crate::core::types::OutputFormat::Csv => {
            crate::pipeline::reporter::write_trend_csv(&report, &output_path)?;
        }
        _ => {
            crate::pipeline::reporter::write_trend_json(&report, &output_path)?;
        }
    }
    Ok(())
}

fn run_tui_cmd(cfg: &RunConfig, _scope: &Scope) -> Result<()> {
    let db_path = Store::default_path();
    let store = Store::new(&db_path)?;
    let mut signals = store.latest_signals()?;
    let mut findings = store.latest_findings()?;
    if signals.is_empty() {
        signals = load_signals_fallback(&cfg.output)?;
    }
    if signals.is_empty() {
        return Err(anyhow!("no stored signals available for TUI"));
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    signals.sort_by(|a, b| a.id.cmp(&b.id));
    run_tui(signals, findings)?;
    Ok(())
}

fn load_signals_fallback(output: &Path) -> Result<Vec<Signal>> {
    let dir = if output.is_dir() || output.extension().is_none() {
        output.to_path_buf()
    } else {
        output
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("out"))
    };
    let jsonl = dir.join("signals.jsonl");
    if jsonl.exists() {
        return load_fixture_signals(&jsonl);
    }
    let json = dir.join("signals.json");
    if json.exists() {
        let data = std::fs::read_to_string(&json)?;
        let parsed: Vec<Signal> = serde_json::from_str(&data)?;
        return Ok(parsed);
    }
    Ok(vec![])
}

fn write_outputs(
    cfg: &RunConfig,
    scope: &Scope,
    signals: &[Signal],
    evidence: &mut [crate::core::types::Evidence],
    detectors: &[String],
) -> Result<ReportPaths> {
    let output_dir = if cfg.output.is_dir() || cfg.output.extension().is_none() {
        cfg.output.clone()
    } else {
        cfg.output
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("out"))
    };
    ensure_output_dir(&output_dir)?;

    let evidence_path = output_dir.join("evidence.jsonl");
    write_evidence_jsonl(evidence, &evidence_path, scope)?;

    let output_path = resolve_output_file(&output_dir, cfg.format, "signals");
    write_signals_output(signals, cfg.format, &output_path)?;

    let manifest_path = cfg
        .manifest
        .clone()
        .unwrap_or_else(|| output_dir.join("manifest.json"));

    Ok(ReportPaths {
        evidence_path,
        output_path,
        manifest_path,
        detectors: detectors.to_vec(),
    })
}

fn persist_run(
    report_paths: &ReportPaths,
    signals: &[Signal],
    findings: &[crate::core::types::Finding],
    scope: &Scope,
    cfg: &RunConfig,
    window: &crate::core::time::RunWindow,
) -> Result<Manifest> {
    let scope_hash = scope_hash(scope)?;
    let cfg_hash = config_hash(cfg);
    let evidence_hash = hash_file(&report_paths.evidence_path)?;
    let output_hash = hash_file(&report_paths.output_path)?;
    let mut detector_list = report_paths.detectors.clone();
    detector_list.sort();

    let manifest = Manifest {
        version: "0.2.0".to_string(),
        git_hash: crate::core::hash::git_hash(),
        scope_hash,
        config_hash: cfg_hash,
        detector_list,
        run_window_start: window.start,
        run_window_end: window.end,
        evidence_hash,
        output_hash,
    };

    write_manifest(&manifest, &report_paths.manifest_path)?;

    let run_id = stable_run_id(&manifest)?;
    let db_path = Store::default_path();
    let mut store = Store::new(&db_path)?;
    store.store_run(&run_id, &manifest, signals, findings)?;
    store.purge_older_than(scope.privacy.max_evidence_retention_days)?;
    Ok(manifest)
}

fn scope_hash(scope: &Scope) -> Result<String> {
    let payload = scope.hash_payload().to_string();
    Ok(sha256_hex(payload.as_bytes()))
}
