use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Clone)]
pub struct RunWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

pub fn run_window() -> RunWindow {
    let now = now_utc();
    RunWindow {
        start: now,
        end: now + Duration::seconds(1),
    }
}

pub fn now_utc() -> DateTime<Utc> {
    if let Ok(value) = std::env::var("BF_FIXED_TIME") {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&value) {
            return dt.with_timezone(&Utc);
        }
    }
    Utc::now()
}

pub fn parse_window(value: &str) -> Result<Duration> {
    let trimmed = value.trim().to_lowercase();
    if let Some(days_str) = trimmed.strip_suffix('d') {
        let days: i64 = days_str
            .parse()
            .map_err(|_| anyhow!("invalid window: {}", value))?;
        if matches!(days, 7 | 30 | 90) {
            return Ok(Duration::days(days));
        }
    }
    Err(anyhow!("invalid window (use 7d|30d|90d): {}", value))
}
