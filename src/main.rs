use std::sync::Arc;
use std::{fs, path::Path};

use bloody_falcon::{
    config::{apply_provider_filter, load_config},
    core::{engine::Engine, error::FalconError},
    ui::{app::App, terminal::run_tui},
};
use clap::Parser;
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
    /// Enable persistent disk cache
    #[arg(long)]
    disk_cache: bool,
    /// Path for disk cache (JSON/SQLite placeholder)
    #[arg(long)]
    disk_cache_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), FalconError> {
    let cli = Cli::parse();

    init_tracing(&cli)?;

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

    if cli.no_tui {
        if app.targets.is_empty() {
            return Err(FalconError::Config(
                "no target provided for headless run; pass a target".into(),
            ));
        }
        let target = &app.targets[0].id.clone();
        let result = engine.scan_username(target, use_cache).await?;
        let json = serde_json::to_string_pretty(&result).map_err(|_| FalconError::Unknown)?;
        println!("{json}");
        Ok(())
    } else {
        run_tui(engine, app, use_cache).await
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
