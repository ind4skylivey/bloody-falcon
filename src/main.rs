use std::sync::Arc;

use bloody_falcon::{
    config::{apply_provider_filter, load_config},
    core::{engine::Engine, error::FalconError},
    ui::{app::App, terminal::run_tui},
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bloody-f4lcon", about = "OSINT terminal recon with live provider checks")]
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
}

#[tokio::main]
async fn main() -> Result<(), FalconError> {
    let cli = Cli::parse();

    let cfg = load_config(cli.config.as_deref())?;
    let cfg = apply_provider_filter(cfg, cli.providers.as_deref());
    let engine = Arc::new(Engine::new(cfg)?);
    let mut app = App::new();
    if let Some(initial) = cli.target {
        app.add_target(initial);
    }
    let use_cache = !cli.no_cache;

    run_tui(engine, app, use_cache).await
}
