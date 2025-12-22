use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::cli::flags::{Cli, Command};
use crate::core::hash::sha256_hex;
use crate::core::scope::{load_scope, Scope};
use crate::core::types::OutputFormat;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub command: CommandName,
    pub scope_path: Option<PathBuf>,
    pub demo_safe: bool,
    pub no_network: bool,
    pub format: OutputFormat,
    pub output: PathBuf,
    pub manifest: Option<PathBuf>,
    #[allow(dead_code)]
    pub policy: Option<PathBuf>,
    pub detectors: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    #[allow(dead_code)]
    pub alerts: Option<String>,
    #[allow(dead_code)]
    pub webhook_url: Option<String>,
    pub trend_window: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandName {
    Scan,
    Replay,
    Report,
    Trend,
}

pub fn resolve_config(cli: &Cli) -> Result<RunConfig> {
    let (command, scope_path, demo_safe, no_network, format_arg, output_opt, manifest_opt) =
        match &cli.command {
            Command::Scan => (
                CommandName::Scan,
                resolve_scope_path(cli)?,
                cli.demo_safe,
                cli.no_network,
                cli.format.clone(),
                cli.output.clone(),
                cli.manifest.clone(),
            ),
            Command::Replay {
                scope,
                client,
                demo_safe,
                no_network,
                format,
                output,
                manifest,
                ..
            } => (
                CommandName::Replay,
                resolve_scope_path_overrides(scope.clone(), client.clone())?,
                *demo_safe,
                *no_network,
                format.clone(),
                output.clone(),
                manifest.clone(),
            ),
            Command::Report {
                scope,
                client,
                demo_safe,
                no_network,
                format,
                output,
            } => (
                CommandName::Report,
                resolve_scope_path_overrides(scope.clone(), client.clone())?,
                *demo_safe,
                *no_network,
                format.clone(),
                output.clone(),
                None,
            ),
            Command::Trend {
                scope,
                client,
                demo_safe,
                no_network,
                format,
                output,
                ..
            } => (
                CommandName::Trend,
                resolve_scope_path_overrides(scope.clone(), client.clone())?,
                *demo_safe,
                *no_network,
                format.clone(),
                output.clone(),
                None,
            ),
        };

    let format = match (&format_arg, command) {
        (Some(fmt), _) => fmt.clone().into(),
        (None, CommandName::Report) => OutputFormat::Markdown,
        (None, CommandName::Trend) => OutputFormat::Markdown,
        (None, _) => OutputFormat::Jsonl,
    };

    let output = output_opt.unwrap_or_else(|| default_output_path(command));

    let manifest = match (manifest_opt, command) {
        (Some(p), _) => Some(p),
        (None, CommandName::Scan | CommandName::Replay) => {
            if output.is_dir() || output.extension().is_none() {
                Some(output.join("manifest.json"))
            } else {
                None
            }
        }
        _ => None,
    };

    let trend_window = match &cli.command {
        Command::Trend { window, .. } => Some(window.clone()),
        _ => None,
    };

    Ok(RunConfig {
        command,
        scope_path,
        demo_safe,
        no_network,
        format,
        output,
        manifest,
        policy: cli.policy.clone(),
        detectors: cli.detectors.clone(),
        sources: cli.sources.clone(),
        alerts: cli.alerts.clone(),
        webhook_url: cli.webhook_url.clone(),
        trend_window,
    })
}

pub fn load_scope_from_config(cfg: &RunConfig) -> Result<Scope> {
    if let Some(path) = &cfg.scope_path {
        return load_scope(path);
    }
    if cfg.demo_safe {
        return Ok(Scope::demo());
    }
    Err(anyhow!("scope is required unless --demo-safe"))
}

pub fn config_hash(cfg: &RunConfig) -> String {
    let payload = serde_json::json!({
        "command": format!("{:?}", cfg.command),
        "demo_safe": cfg.demo_safe,
        "no_network": cfg.no_network,
        "format": format!("{:?}", cfg.format),
        "output": cfg.output.to_string_lossy(),
        "manifest": cfg.manifest.as_ref().map(|p| p.to_string_lossy().to_string()),
        "detectors": cfg.detectors.clone().unwrap_or_default(),
        "sources": cfg.sources.clone().unwrap_or_default(),
        "trend_window": cfg.trend_window.clone().unwrap_or_default(),
    });
    sha256_hex(payload.to_string().as_bytes())
}

fn resolve_scope_path(cli: &Cli) -> Result<Option<PathBuf>> {
    if let Some(path) = &cli.scope {
        return Ok(Some(path.clone()));
    }
    if let Some(client) = &cli.client {
        let path = Path::new("clients").join(format!("{}.toml", client));
        return Ok(Some(path));
    }
    Ok(None)
}

fn resolve_scope_path_overrides(
    scope: Option<PathBuf>,
    client: Option<String>,
) -> Result<Option<PathBuf>> {
    if let Some(path) = scope {
        return Ok(Some(path));
    }
    if let Some(client) = client {
        let path = Path::new("clients").join(format!("{}.toml", client));
        return Ok(Some(path));
    }
    Ok(None)
}

fn default_output_path(command: CommandName) -> PathBuf {
    match command {
        CommandName::Report => PathBuf::from("out/report.md"),
        CommandName::Trend => PathBuf::from("out/trend.md"),
        _ => PathBuf::from("out"),
    }
}

pub fn format_extension(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Json => "json",
        OutputFormat::Jsonl => "jsonl",
        OutputFormat::Markdown => "md",
        OutputFormat::Sarif => "sarif",
        OutputFormat::Csv => "csv",
    }
}

pub fn ensure_output_dir(path: &Path) -> Result<()> {
    if path.exists() && path.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub fn resolve_output_file(output: &Path, format: OutputFormat, default_name: &str) -> PathBuf {
    if output.is_dir() || output.extension().is_none() {
        output.join(format!("{}.{}", default_name, format_extension(format)))
    } else {
        output.to_path_buf()
    }
}
