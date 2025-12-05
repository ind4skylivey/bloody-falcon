use std::{fs, path::Path};

use serde::Deserialize;

use crate::core::error::FalconError;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub enabled: bool,
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub timeout_ms: u64,
    pub max_concurrent_requests: usize,
    pub cache_ttl_seconds: u64,
    pub providers: Vec<ProviderConfig>,
}

pub fn load_config(path: Option<&str>) -> Result<AppConfig, FalconError> {
    let default_path = Path::new("config/bloodyf4lcon.toml");
    let path = path.map(Path::new).unwrap_or(default_path);

    if !path.exists() {
        return Ok(default_config());
    }

    let content = fs::read_to_string(path).map_err(|e| FalconError::Config(e.to_string()))?;
    let cfg: AppConfig =
        toml::from_str(&content).map_err(|e| FalconError::Config(e.to_string()))?;
    Ok(cfg)
}

pub fn apply_provider_filter(cfg: AppConfig, names: Option<&[String]>) -> AppConfig {
    if let Some(list) = names {
        let mut cfg = cfg;
        let lowered: Vec<String> = list.iter().map(|s| s.to_lowercase()).collect();
        for p in cfg.providers.iter_mut() {
            p.enabled = lowered.iter().any(|n| n == &p.name.to_lowercase());
        }
        return cfg;
    }
    cfg
}

fn default_config() -> AppConfig {
    AppConfig {
        timeout_ms: 5_000,
        max_concurrent_requests: 5,
        cache_ttl_seconds: 600,
        providers: vec![
            ProviderConfig {
                name: "github".to_string(),
                enabled: true,
                base_url: "https://github.com/{username}".to_string(),
            },
            ProviderConfig {
                name: "reddit".to_string(),
                enabled: true,
                base_url: "https://www.reddit.com/user/{username}".to_string(),
            },
            ProviderConfig {
                name: "steam".to_string(),
                enabled: true,
                base_url: "https://steamcommunity.com/id/{username}".to_string(),
            },
            ProviderConfig {
                name: "twitter".to_string(),
                enabled: true,
                base_url: "https://twitter.com/{username}".to_string(),
            },
            ProviderConfig {
                name: "psnprofiles".to_string(),
                enabled: true,
                base_url: "https://psnprofiles.com/{username}".to_string(),
            },
        ],
    }
}
