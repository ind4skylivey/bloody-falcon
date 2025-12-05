use std::{collections::HashMap, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::core::{engine::ReconResult, error::FalconError};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct StoredEntry {
    result: ReconResult,
    timestamp_ms: u128,
}

pub struct DiskCache {
    path: std::path::PathBuf,
}

impl DiskCache {
    pub fn new(path: &Path) -> Result<Self, FalconError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| FalconError::Config(e.to_string()))?;
        }
        if !path.exists() {
            fs::write(path, b"{}\n").map_err(|e| FalconError::Config(e.to_string()))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn get(&self, username: &str, ttl: Duration) -> Result<Option<ReconResult>, FalconError> {
        let map = self.read_map()?;
        if let Some(entry) = map.get(username) {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .saturating_sub(entry.timestamp_ms);
            if age < ttl.as_millis() {
                return Ok(Some(entry.result.clone()));
            }
        }
        Ok(None)
    }

    pub fn put(&self, username: &str, result: &ReconResult) -> Result<(), FalconError> {
        let mut map = self.read_map()?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        map.insert(
            username.to_string(),
            StoredEntry {
                result: result.clone(),
                timestamp_ms: now_ms,
            },
        );
        self.write_map(&map)
    }

    pub fn purge_expired(&self, ttl: Duration) -> Result<(), FalconError> {
        let mut map = self.read_map()?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        map.retain(|_, entry| now_ms.saturating_sub(entry.timestamp_ms) < ttl.as_millis());
        self.write_map(&map)
    }

    fn read_map(&self) -> Result<HashMap<String, StoredEntry>, FalconError> {
        let data =
            fs::read_to_string(&self.path).map_err(|e| FalconError::Config(e.to_string()))?;
        let map: HashMap<String, StoredEntry> = serde_json::from_str(&data).unwrap_or_default();
        Ok(map)
    }

    fn write_map(&self, map: &HashMap<String, StoredEntry>) -> Result<(), FalconError> {
        let json = serde_json::to_string_pretty(map).map_err(|_| FalconError::Unknown)?;
        fs::write(&self.path, json).map_err(|e| FalconError::Config(e.to_string()))
    }
}
