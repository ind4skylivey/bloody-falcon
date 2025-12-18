use std::path::Path;

use anyhow::{anyhow, Result};
use regex::Regex;
use serde::Deserialize;

use crate::core::types::Severity;

#[derive(Debug, Clone)]
pub struct Scope {
    pub brand_terms: Vec<String>,
    pub domains: Vec<String>,
    pub products: Vec<String>,
    pub official_handles: Vec<String>,
    pub allowed_sources: Vec<String>,
    pub allowed_detectors: Vec<String>,
    pub watch_keywords: Vec<String>,
    pub negative_keywords: Vec<String>,
    pub privacy: Privacy,
    pub policy: PolicyConfig,
    pub rate_limits: RateLimits,
    pub typosquat: TyposquatConfig,
}

#[derive(Debug, Clone)]
pub struct Privacy {
    pub store_raw: bool,
    pub redact_patterns: Vec<Regex>,
    pub redact_patterns_raw: Vec<String>,
    pub max_evidence_retention_days: u32,
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub min_confidence_alert: u8,
    pub min_severity_alert: Severity,
    pub digest_frequency: String,
    pub typosquat: TyposquatPolicy,
}

#[derive(Debug, Clone)]
pub struct TyposquatPolicy {
    pub generic_tokens: Vec<String>,
    pub old_domain_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimits {
    #[serde(default = "default_github_ms")]
    pub github_min_interval_ms: u64,
    #[serde(default = "default_paste_ms")]
    pub paste_min_interval_ms: u64,
    #[serde(default = "default_ct_ms")]
    pub ct_min_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TyposquatConfig {
    #[serde(default = "default_locale")]
    pub locale: String,
    #[serde(default = "default_distance")]
    pub distance_weight: u8,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            github_min_interval_ms: default_github_ms(),
            paste_min_interval_ms: default_paste_ms(),
            ct_min_interval_ms: default_ct_ms(),
        }
    }
}

impl Default for TyposquatConfig {
    fn default() -> Self {
        Self {
            locale: default_locale(),
            distance_weight: default_distance(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ScopeRaw {
    #[serde(default)]
    brand_terms: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    products: Vec<String>,
    #[serde(default)]
    official_handles: Vec<String>,
    #[serde(default)]
    allowed_sources: Vec<String>,
    #[serde(default)]
    allowed_detectors: Vec<String>,
    #[serde(default)]
    watch_keywords: Vec<String>,
    #[serde(default)]
    negative_keywords: Vec<String>,
    #[serde(default)]
    privacy: PrivacyRaw,
    #[serde(default)]
    policy: PolicyRaw,
    #[serde(default)]
    rate_limits: RateLimits,
    #[serde(default)]
    typosquat: TyposquatConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PrivacyRaw {
    #[serde(default)]
    store_raw: bool,
    #[serde(default)]
    redact_patterns: Vec<String>,
    #[serde(default = "default_retention")]
    max_evidence_retention_days: u32,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PolicyRaw {
    #[serde(default = "default_min_conf")]
    min_confidence_alert: u8,
    #[serde(default = "default_min_sev")]
    min_severity_alert: String,
    #[serde(default = "default_digest")]
    digest_frequency: String,
    #[serde(default)]
    typosquat: TyposquatPolicyRaw,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct TyposquatPolicyRaw {
    #[serde(default)]
    generic_tokens: Vec<String>,
    #[serde(default = "default_old_domain_days")]
    old_domain_days: u32,
}

pub fn load_scope(path: &Path) -> Result<Scope> {
    let data = std::fs::read_to_string(path)?;
    let raw: ScopeRaw = toml::from_str(&data)?;
    Scope::from_raw(raw)
}

impl Scope {
    pub fn demo() -> Self {
        Self {
            brand_terms: vec![],
            domains: vec![],
            products: vec![],
            official_handles: vec![],
            allowed_sources: vec!["fixture".to_string()],
            allowed_detectors: vec!["typosquat".to_string()],
            watch_keywords: vec![],
            negative_keywords: vec![],
            privacy: Privacy {
                store_raw: false,
                redact_patterns: vec![],
                redact_patterns_raw: vec![],
                max_evidence_retention_days: 7,
            },
            policy: PolicyConfig {
                min_confidence_alert: 80,
                min_severity_alert: Severity::High,
                digest_frequency: "daily".to_string(),
                typosquat: TyposquatPolicy {
                    generic_tokens: default_generic_tokens(),
                    old_domain_days: default_old_domain_days(),
                },
            },
            rate_limits: RateLimits {
                github_min_interval_ms: default_github_ms(),
                paste_min_interval_ms: default_paste_ms(),
                ct_min_interval_ms: default_ct_ms(),
            },
            typosquat: TyposquatConfig {
                locale: default_locale(),
                distance_weight: default_distance(),
            },
        }
    }

    pub fn sanitize_for_demo(&self) -> Self {
        let mut safe = self.clone();
        safe.allowed_sources = vec!["fixture".to_string(), "offline".to_string()];
        safe.allowed_detectors = vec!["typosquat".to_string()];
        safe
    }

    pub(crate) fn from_raw(raw: ScopeRaw) -> Result<Self> {
        let mut compiled = Vec::new();
        for pat in raw.privacy.redact_patterns.iter() {
            compiled.push(Regex::new(pat)?);
        }
        let min_sev = if raw.policy.min_severity_alert.trim().is_empty() {
            default_min_sev()
        } else {
            raw.policy.min_severity_alert.clone()
        };
        let sev = parse_severity(&min_sev)?;
        let typosquat_policy = TyposquatPolicy {
            generic_tokens: if raw.policy.typosquat.generic_tokens.is_empty() {
                default_generic_tokens()
            } else {
                raw.policy
                    .typosquat
                    .generic_tokens
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect()
            },
            old_domain_days: raw.policy.typosquat.old_domain_days,
        };
        let rate_limits = sanitize_rate_limits(raw.rate_limits.clone());
        Ok(Self {
            brand_terms: raw.brand_terms,
            domains: raw.domains,
            products: raw.products,
            official_handles: raw.official_handles,
            allowed_sources: raw.allowed_sources,
            allowed_detectors: raw.allowed_detectors,
            watch_keywords: raw.watch_keywords,
            negative_keywords: raw.negative_keywords,
            privacy: Privacy {
                store_raw: raw.privacy.store_raw,
                redact_patterns: compiled,
                redact_patterns_raw: raw.privacy.redact_patterns,
                max_evidence_retention_days: raw.privacy.max_evidence_retention_days,
            },
            policy: PolicyConfig {
                min_confidence_alert: raw.policy.min_confidence_alert,
                min_severity_alert: sev,
                digest_frequency: raw.policy.digest_frequency,
                typosquat: typosquat_policy,
            },
            rate_limits,
            typosquat: raw.typosquat,
        })
    }

    pub fn validate(&self, demo_safe: bool) -> Result<()> {
        if demo_safe {
            if !self.privacy.store_raw
                && self.privacy.redact_patterns.is_empty()
                && (!self.domains.is_empty() || !self.brand_terms.is_empty())
            {
                return Err(anyhow!(
                    "privacy.store_raw=false requires redact_patterns when scope includes data"
                ));
            }
            return Ok(());
        }
        if self.domains.is_empty() && self.brand_terms.is_empty() {
            return Err(anyhow!("scope must include domains or brand_terms"));
        }
        if self.allowed_sources.is_empty() {
            return Err(anyhow!("scope must include allowed_sources"));
        }
        if self.allowed_detectors.is_empty() {
            return Err(anyhow!("scope must include allowed_detectors"));
        }
        if !self.privacy.store_raw && self.privacy.redact_patterns.is_empty() {
            return Err(anyhow!(
                "privacy.store_raw=false requires redact_patterns to avoid raw data retention"
            ));
        }
        Ok(())
    }

    pub fn hash_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "brand_terms": self.brand_terms,
            "domains": self.domains,
            "products": self.products,
            "official_handles": self.official_handles,
            "allowed_sources": self.allowed_sources,
            "allowed_detectors": self.allowed_detectors,
            "watch_keywords": self.watch_keywords,
            "negative_keywords": self.negative_keywords,
            "privacy": {
                "store_raw": self.privacy.store_raw,
                "redact_patterns": self.privacy.redact_patterns_raw,
                "max_evidence_retention_days": self.privacy.max_evidence_retention_days
            },
            "policy": {
                "min_confidence_alert": self.policy.min_confidence_alert,
                "min_severity_alert": format!("{:?}", self.policy.min_severity_alert),
                "digest_frequency": self.policy.digest_frequency,
                "typosquat": {
                    "generic_tokens": self.policy.typosquat.generic_tokens,
                    "old_domain_days": self.policy.typosquat.old_domain_days
                }
            },
            "rate_limits": {
                "github_min_interval_ms": self.rate_limits.github_min_interval_ms,
                "paste_min_interval_ms": self.rate_limits.paste_min_interval_ms,
                "ct_min_interval_ms": self.rate_limits.ct_min_interval_ms
            },
            "typosquat": {
                "locale": self.typosquat.locale,
                "distance_weight": self.typosquat.distance_weight
            }
        })
    }
}

fn parse_severity(value: &str) -> Result<Severity> {
    match value.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(anyhow!("invalid severity: {}", value)),
    }
}

fn default_retention() -> u32 {
    30
}

fn sanitize_rate_limits(mut limits: RateLimits) -> RateLimits {
    if limits.github_min_interval_ms == 0 {
        limits.github_min_interval_ms = default_github_ms();
    }
    if limits.paste_min_interval_ms == 0 {
        limits.paste_min_interval_ms = default_paste_ms();
    }
    if limits.ct_min_interval_ms == 0 {
        limits.ct_min_interval_ms = default_ct_ms();
    }
    limits
}

fn default_min_conf() -> u8 {
    80
}

fn default_min_sev() -> String {
    "high".to_string()
}

fn default_digest() -> String {
    "daily".to_string()
}

fn default_generic_tokens() -> Vec<String> {
    vec![
        "login".to_string(),
        "secure".to_string(),
        "support".to_string(),
        "billing".to_string(),
        "account".to_string(),
        "verify".to_string(),
    ]
}

fn default_old_domain_days() -> u32 {
    180
}

fn default_github_ms() -> u64 {
    1000
}

fn default_paste_ms() -> u64 {
    800
}

fn default_ct_ms() -> u64 {
    500
}

fn default_locale() -> String {
    "us".to_string()
}

fn default_distance() -> u8 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_validation_requires_terms_or_domains() {
        let scope = Scope::from_raw(ScopeRaw {
            brand_terms: vec![],
            domains: vec![],
            products: vec![],
            official_handles: vec![],
            allowed_sources: vec!["x".to_string()],
            allowed_detectors: vec!["y".to_string()],
            watch_keywords: vec![],
            negative_keywords: vec![],
            privacy: PrivacyRaw::default(),
            policy: PolicyRaw::default(),
            rate_limits: RateLimits {
                github_min_interval_ms: 1,
                paste_min_interval_ms: 1,
                ct_min_interval_ms: 1,
            },
            typosquat: TyposquatConfig {
                locale: "us".to_string(),
                distance_weight: 1,
            },
        })
        .unwrap();

        let result = scope.validate(false);
        assert!(result.is_err());
    }
}
