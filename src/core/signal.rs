use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// High-level categorization for an OSINT signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalType {
    Impersonation,
    TyposquatDomain,
    NewCert,
    LeakIndicator,
    MentionSpike,
    MalwareLure,
}

/// Severity mapped for SOC consumption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// Evidence that supports a signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub source: String,
    pub url: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub note: Option<String>,
}

/// Normalized signal model to aggregate and alert on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signal {
    pub signal_type: SignalType,
    pub subject: String,
    pub evidence: Vec<Evidence>,
    pub confidence: u8,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub recommended_action: String,
    /// Stable fingerprint for deduplication and trend tracking.
    pub fingerprint: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Signal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signal_type: SignalType,
        subject: impl Into<String>,
        evidence: Vec<Evidence>,
        confidence: u8,
        severity: Severity,
        tags: Vec<String>,
        recommended_action: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            signal_type,
            subject: subject.into(),
            evidence,
            confidence,
            severity,
            tags,
            recommended_action: recommended_action.into(),
            fingerprint: fingerprint.into(),
            first_seen: now,
            last_seen: now,
        }
    }
}
