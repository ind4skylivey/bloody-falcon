use std::{fs, path::Path};

use serde::Deserialize;

use super::error::FalconError;

/// Client scope definition loaded from client.toml
#[derive(Debug, Clone, Deserialize)]
pub struct ClientScope {
    #[serde(default)]
    pub brand_terms: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub executives: Vec<String>,
    #[serde(default)]
    pub approved_assets: Vec<String>,
    #[serde(default)]
    pub watchlists: Vec<String>,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default)]
    pub alert_policy: Option<AlertPolicy>,
    #[serde(default)]
    pub rate_limits: RateLimits,
    #[serde(default)]
    pub typosquat_locale: Option<String>,
    #[serde(default)]
    pub typosquat_distance_weight: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertPolicy {
    pub immediate_threshold: Option<Threshold>,
    #[serde(default)]
    pub digest_frequency: DigestFrequency,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Threshold {
    pub severity: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DigestFrequency {
    #[default]
    Daily,
    Weekly,
    Off,
}

pub fn load_scope(path: &Path) -> Result<ClientScope, FalconError> {
    let data = fs::read_to_string(path).map_err(|e| FalconError::Config(e.to_string()))?;
    let scope: ClientScope =
        toml::from_str(&data).map_err(|e| FalconError::Config(format!("scope: {e}")))?;
    Ok(scope)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimits {
    #[serde(default = "default_paste_ms")]
    pub paste_min_interval_ms: u64,
    #[serde(default = "default_github_ms")]
    pub github_min_interval_ms: u64,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            paste_min_interval_ms: default_paste_ms(),
            github_min_interval_ms: default_github_ms(),
        }
    }
}

fn default_paste_ms() -> u64 {
    800
}
fn default_github_ms() -> u64 {
    1000
}
