use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: String,
    pub observed_at: DateTime<Utc>,
    pub url: Option<String>,
    pub note: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub id: String,
    pub signal_type: SignalType,
    pub subject: String,
    pub source: String,
    pub evidence_ref: String,
    pub timestamp: DateTime<Utc>,
    pub indicators: Vec<Indicator>,
    pub confidence: u8,
    pub severity: Severity,
    pub rationale: String,
    pub recommended_actions: Vec<String>,
    pub dedupe_key: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub suppression_reason: Option<String>,
    #[serde(default)]
    pub policy_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalType {
    Impersonation,
    TyposquatDomain,
    NewCert,
    ExposureCode,
    ExposurePaste,
    MentionSpike,
    ThreatFeedMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Indicator(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Score {
    pub confidence: u8,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub signals: Vec<String>,
    pub confidence: u8,
    pub severity: Severity,
    pub rationale: String,
    pub rule_trace: Vec<String>,
    #[serde(default)]
    pub disposition: FindingDisposition,
    #[serde(default)]
    pub policy_gates: Vec<String>,
    #[serde(default)]
    pub blocked_by: Option<String>,
    #[serde(default)]
    pub suppression_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum FindingDisposition {
    Alert,
    Investigate,
    #[default]
    Digest,
    Suppressed,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub min_confidence_alert: u8,
    pub min_severity_alert: Severity,
    pub digest_frequency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub git_hash: String,
    pub scope_hash: String,
    pub config_hash: String,
    pub detector_list: Vec<String>,
    pub run_window_start: DateTime<Utc>,
    pub run_window_end: DateTime<Utc>,
    pub evidence_hash: String,
    pub output_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Markdown,
    Sarif,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendReport {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub by_signal_type: Vec<TrendBucket>,
    pub by_subject: Vec<TrendBucket>,
    pub by_dedupe_key: Vec<TrendBucket>,
    pub summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendBucket {
    pub key: String,
    pub count: u64,
    pub prev_count: u64,
    pub delta: i64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_seen_in_window: bool,
}
