use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;

use crate::{
    config::{AppConfig, ProviderConfig},
    core::error::FalconError,
    modules::recon::username::check_provider,
};

#[derive(Clone, Debug)]
pub struct ReconResult {
    pub hits: usize,
    pub platforms: Vec<String>,
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
}

impl Engine {
    pub fn new(config: AppConfig) -> Result<Self, FalconError> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let client = reqwest::Client::builder()
            .user_agent("bloody-f4lcon/1.0 (production)")
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(4))
            .build()
            .map_err(FalconError::from)?;

        Ok(Self {
            client,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            cache: Mutex::new(HashMap::new()),
            config,
        })
    }

    pub async fn scan_username(&self, username: &str, use_cache: bool) -> Result<ReconResult, FalconError> {
        if use_cache {
            if let Some(result) = self.check_cache(username) {
                return Ok(result);
            }
        }

        let mut hits = 0usize;
        let mut platforms = Vec::new();

        for provider in self
            .config
            .providers
            .iter()
            .cloned()
            .filter(|p| p.enabled)
        {
            let permit = self.semaphore.acquire().await.map_err(|_| FalconError::Unknown)?;
            let ok = check_one(&self.client, &provider, username).await;
            drop(permit);

            match ok {
                Ok(true) => {
                    hits += 1;
                    platforms.push(provider.name);
                }
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!("provider {} error: {}", provider.name, err);
                }
            }
        }

        let result = ReconResult { hits, platforms };

        if use_cache && self.config.cache_ttl_seconds > 0 {
            let mut cache = self.cache.lock().expect("cache poisoned");
            cache.insert(
                username.to_string(),
                CachedResult {
                    result: result.clone(),
                    timestamp: Instant::now(),
                },
            );
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
) -> Result<bool, FalconError> {
    check_provider(client, provider, username).await
}
