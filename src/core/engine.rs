use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;

use crate::{
    config::{AppConfig, ProviderConfig},
    core::disk_cache::DiskCache,
    core::error::FalconError,
    modules::recon::username::check_provider,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconResult {
    pub hits: usize,
    pub platforms: Vec<String>,
    pub failed: Vec<String>,
    pub restricted: Vec<String>,
    pub rate_limited: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CachedResult {
    pub result: ReconResult,
    pub timestamp: Instant,
}

pub struct Engine {
    client: reqwest::Client,
    pub config: AppConfig,
    semaphore: Arc<Semaphore>,
    cache: Mutex<HashMap<String, CachedResult>>,
    disk_cache: Option<DiskCache>,
}

impl Engine {
    pub fn new(config: AppConfig) -> Result<Self, FalconError> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let client = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(4))
            .build()
            .map_err(FalconError::from)?;

        let disk_cache = if config.disk_cache_enabled {
            Some(DiskCache::new(std::path::Path::new(
                &config.disk_cache_path,
            ))?)
        } else {
            None
        };

        Ok(Self {
            client,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            cache: Mutex::new(HashMap::new()),
            disk_cache,
            config,
        })
    }

    /// Construct a provider URL for a username if the provider is known.
    pub fn provider_url(&self, provider_name: &str, username: &str) -> Option<String> {
        self.config
            .providers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(provider_name))
            .map(|p| p.base_url.replace("{username}", username))
    }

    pub async fn scan_username(
        &self,
        username: &str,
        use_cache: bool,
    ) -> Result<ReconResult, FalconError> {
        if use_cache {
            if let Some(result) = self.check_cache(username) {
                return Ok(result);
            }
            if let Some(disk) = &self.disk_cache {
                match disk.get(username, Duration::from_secs(self.config.cache_ttl_seconds)) {
                    Ok(Some(result)) => return Ok(result),
                    Ok(None) => {}
                    Err(e) => tracing::warn!("disk cache read error: {}", e),
                }
            }
        }

        let mut hits = 0usize;
        let mut platforms = Vec::new();
        let mut failed = Vec::new();
        let mut restricted = Vec::new();
        let mut rate_limited = Vec::new();

        for provider in self.config.providers.iter().filter(|p| p.enabled).cloned() {
            let permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_| FalconError::Unknown)?;
            let ok = check_one(&self.client, &provider, username).await;
            drop(permit);

            match ok {
                Ok(ProviderOutcome::Hit) => {
                    hits += 1;
                    platforms.push(provider.name);
                }
                Ok(ProviderOutcome::Miss) => {}
                Ok(ProviderOutcome::Restricted) => restricted.push(provider.name),
                Ok(ProviderOutcome::RateLimited) => rate_limited.push(provider.name),
                Err(err) => failed.push(format!("{}: {}", provider.name, err)),
            }
        }

        let result = ReconResult {
            hits,
            platforms,
            failed,
            restricted,
            rate_limited,
        };

        if use_cache && self.config.cache_ttl_seconds > 0 {
            let mut cache = self.cache.lock().expect("cache poisoned");
            cache.insert(
                username.to_string(),
                CachedResult {
                    result: result.clone(),
                    timestamp: Instant::now(),
                },
            );
            if let Some(disk) = &self.disk_cache {
                let _ = disk.purge_expired(Duration::from_secs(self.config.cache_ttl_seconds));
                if let Err(e) = disk.put(username, &result) {
                    tracing::warn!("disk cache write error: {}", e);
                }
            }
        }

        Ok(result)
    }

    fn check_cache(&self, username: &str) -> Option<ReconResult> {
        if self.config.cache_ttl_seconds == 0 {
            return None;
        }
        let ttl = Duration::from_secs(self.config.cache_ttl_seconds);
        let cache = self.cache.lock().ok()?;
        cache.get(username).and_then(|entry| {
            if entry.timestamp.elapsed() < ttl {
                Some(entry.result.clone())
            } else {
                None
            }
        })
    }
}

async fn check_one(
    client: &reqwest::Client,
    provider: &ProviderConfig,
    username: &str,
) -> Result<ProviderOutcome, FalconError> {
    let mut delay = Duration::from_millis(300);
    for attempt in 0..3 {
        match check_provider(client, provider, username).await? {
            ProviderOutcome::RateLimited if attempt < 2 => {
                tokio::time::sleep(delay).await;
                delay *= 2;
                continue;
            }
            other => return Ok(other),
        }
    }
    Ok(ProviderOutcome::RateLimited)
}
#[derive(Debug, Clone)]
pub enum ProviderOutcome {
    Hit,
    Miss,
    Restricted,
    RateLimited,
}
