use std::sync::Arc;
use std::{fs, path::Path, time::Duration};

use bloody_falcon::{
    config::{apply_provider_filter, load_config},
    core::{
        alert::{meets_threshold, send_webhook_alert},
        engine::Engine,
        error::FalconError,
        output::{write_signals, OutputFormat},
        scope::{load_scope, ClientScope},
        signal::Signal,
        signal_utils::{allows, parse_severity, recon_to_signals},
        store::SignalStore,
    },
    modules::detections::{ct_log_signals, leak_keyword_signals, paste_signals, typosquat_signals},
    ui::{app::App, terminal::run_tui},
};
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, ValueEnum};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "bloody-f4lcon",
    about = "OSINT terminal recon with live provider checks"
)]
struct Cli {
    /// Path to config file (TOML). Default: config/bloodyf4lcon.toml
    #[arg(long)]
    config: Option<String>,
    /// Comma-separated provider names to enable (case-insensitive)
    #[arg(long, value_delimiter = ',')]
    providers: Option<Vec<String>>,
    /// Disable in-memory cache
    #[arg(long)]
    no_cache: bool,
    /// Optional initial target
    target: Option<String>,
    /// Optional label for the initial target
    #[arg(long)]
    label: Option<String>,
    /// Increase verbosity (info, debug)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Optional log file path
    #[arg(long, default_value = "data/falcon.log")]
    log_file: String,
    /// Run without TUI; print JSON result to stdout
    #[arg(long)]
    no_tui: bool,
    /// Client scope file (TOML). Mandatory unless --demo
    #[arg(long)]
    scope: Option<String>,
    /// Allow running without scope (demo mode)
    #[arg(long)]
    demo: bool,
    /// Output format for signals (headless)
    #[arg(long, default_value = "jsonl", value_enum)]
    format: FormatArg,
    /// Output file path for signals
    #[arg(long, default_value = "data/signals.jsonl")]
    output: String,
    /// SQLite path for signals/history
    #[arg(long, default_value = "data/falcon.db")]
    db_path: String,
    /// Emit daily digest (Markdown) from last 24h
    #[arg(long)]
    digest: bool,
    /// Digest output folder (files named by date)
    #[arg(long, default_value = "data/digests")]
    digest_dir: String,
    /// Only alert on newly created signals (default true)
    #[arg(long, default_value_t = true)]
    alerts_new_only: bool,
    /// Only include new signals in digest (default true)
    #[arg(long, default_value_t = true)]
    digest_new_only: bool,
    /// Webhook URL for immediate alerts (Slack/Generic)
    #[arg(long)]
    alert_webhook: Option<String>,
    /// Enable persistent disk cache
    #[arg(long)]
    disk_cache: bool,
    /// Path for disk cache (JSON/SQLite placeholder)
    #[arg(long)]
    disk_cache_path: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
enum FormatArg {
    Jsonl,
    Sarif,
    Md,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Jsonl => OutputFormat::Jsonl,
            FormatArg::Sarif => OutputFormat::Sarif,
            FormatArg::Md => OutputFormat::Markdown,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), FalconError> {
    let cli = Cli::parse();

    init_tracing(&cli)?;

    let scope_path = cli.scope.as_deref();
    let demo_mode = cli.demo || scope_path.is_none();
    let mut scope_loaded: Option<ClientScope> = None;
    if demo_mode {
        tracing::warn!("Running in demo mode: no client scope provided; signals are generic.");
    } else if let Some(scope_str) = scope_path {
        let path = Path::new(scope_str);
        if !path.exists() {
            return Err(FalconError::Config(format!(
                "scope file not found: {}",
                path.display()
            )));
        }
        let scope = load_scope(path)?;
        tracing::info!("Scope loaded from {}", path.display());
        scope_loaded = Some(scope);
    }

    let mut cfg = load_config(cli.config.as_deref())?;
    cfg = apply_provider_filter(cfg, cli.providers.as_deref());
    if cli.disk_cache {
        cfg.disk_cache_enabled = true;
    }
    if let Some(path) = cli.disk_cache_path {
        cfg.disk_cache_enabled = true;
        cfg.disk_cache_path = path;
    }
    let engine = Arc::new(Engine::new(cfg)?);
    let mut app = App::new();
    if let Some(initial) = cli.target {
        app.add_target_with_label(initial, cli.label);
    }
    let use_cache = !cli.no_cache;
    let output_format: OutputFormat = cli.format.into();

    if cli.no_tui {
        if app.targets.is_empty() {
            return Err(FalconError::Config(
                "no target provided for headless run; pass a target".into(),
            ));
        }
        let mut store = SignalStore::new(Path::new(&cli.db_path))?;
        let http_client = reqwest::Client::builder()
            .user_agent(engine.config.user_agent.clone())
            .timeout(Duration::from_millis(engine.config.timeout_ms))
            .build()
            .map_err(FalconError::from)?;

        let target = &app.targets[0].id.clone();
        let result = engine.scan_username(target, use_cache).await?;
        let mut signals = recon_to_signals(target, &result, &engine, demo_mode);
        let github_token = std::env::var("GITHUB_TOKEN").ok();
        let paste_token = std::env::var("PASTE_TOKEN").ok();

        if let Some(scope) = &scope_loaded {
            if allows(scope, "typosquat") {
                signals.extend(typosquat_signals(scope, &http_client).await?);
            }
            if allows(scope, "ct-logs") {
                signals.extend(ct_log_signals(scope, &http_client).await?);
            }
            if allows(scope, "leak-keywords") {
                signals.extend(
                    leak_keyword_signals(scope, &http_client, github_token.as_deref()).await?,
                );
            }
            if allows(scope, "paste") {
                signals.extend(
                    paste_signals(
                        scope,
                        &http_client,
                        paste_token.as_deref(),
                        github_token.as_deref(),
                    )
                    .await?,
                );
            }
        }

        let new_signals = store.upsert_signals(&signals)?;
        if cli.digest {
            let since = Utc::now() - ChronoDuration::hours(24);
            let recent = if cli.digest_new_only {
                new_signals.clone()
            } else {
                store.fetch_since(since)?
            };
            let digest_dir = Path::new(&cli.digest_dir);
            fs::create_dir_all(digest_dir).map_err(|e| FalconError::Config(e.to_string()))?;
            let digest_path = digest_dir.join(format!("digest-{}.md", Utc::now().date_naive()));
            write_signals(&recent, OutputFormat::Markdown, &digest_path)?;
            tracing::info!("Daily digest written to {}", digest_path.display());
        }

        if let (Some(scope), Some(webhook)) = (&scope_loaded, &cli.alert_webhook) {
            if let Some(policy) = &scope.alert_policy {
                if let Some(th) = &policy.immediate_threshold {
                    if let Some(sev_floor) = parse_severity(&th.severity) {
                        let pool = if cli.alerts_new_only {
                            &new_signals
                        } else {
                            &signals
                        };
                        let to_alert: Vec<Signal> = pool
                            .iter()
                            .filter(|s| meets_threshold(s, &sev_floor, th.confidence))
                            .cloned()
                            .collect();
                        if !to_alert.is_empty() {
                            send_webhook_alert(&http_client, webhook, &to_alert).await?;
                            tracing::info!("Sent {} signals via webhook", to_alert.len());
                        }
                    }
                }
            }
        }

        let out_path = Path::new(&cli.output);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| FalconError::Config(e.to_string()))?;
        }
        write_signals(&signals, output_format, out_path)?;
        let json = serde_json::to_string_pretty(&signals).map_err(|_| FalconError::Unknown)?;
        println!("{json}");
        Ok(())
    } else {
        let scope_arc = scope_loaded.map(Arc::new);
        run_tui(engine, app, use_cache, scope_arc, demo_mode).await
    }
}

fn init_tracing(cli: &Cli) -> Result<(), FalconError> {
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let log_path = Path::new(&cli.log_file);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(|e| FalconError::Config(e.to_string()))?;
    }
    if log_path.exists() {
        if let Ok(meta) = fs::metadata(log_path) {
            if meta.len() > 1_000_000 {
                let rotated = log_path.with_extension("log.1");
                let _ = fs::rename(log_path, rotated);
            }
        }
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| FalconError::Config(e.to_string()))?;

    let file_layer = fmt::layer()
        .with_writer(file)
        .with_ansi(false)
        .with_target(false);

    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_target(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .try_init()
        .map_err(|e| FalconError::Config(e.to_string()))
}
