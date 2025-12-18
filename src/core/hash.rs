use sha2::{Digest, Sha256};

use crate::core::types::{Indicator, Manifest, SignalType};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn stable_signal_id(
    signal_type: &SignalType,
    subject: &str,
    evidence_ref: &str,
    indicators: &[Indicator],
) -> String {
    let mut ordered: Vec<String> = indicators.iter().map(|i| i.0.clone()).collect();
    ordered.sort();
    let mut buf = String::new();
    buf.push_str(&format!("{:?}", signal_type));
    buf.push('|');
    buf.push_str(subject);
    buf.push('|');
    buf.push_str(evidence_ref);
    buf.push('|');
    buf.push_str(&ordered.join(","));
    format!("sig_{}", sha256_hex(buf.as_bytes()))
}

pub fn dedupe_key(signal_type: &SignalType, subject: &str, indicators: &[Indicator]) -> String {
    let mut ordered: Vec<String> = indicators.iter().map(|i| i.0.clone()).collect();
    ordered.sort();
    format!("{:?}:{}:{}", signal_type, subject, ordered.join(","))
}

pub fn stable_run_id(manifest: &Manifest) -> anyhow::Result<String> {
    let json = serde_json::to_string(manifest)?;
    Ok(format!("run_{}", sha256_hex(json.as_bytes())))
}

pub fn git_hash() -> String {
    std::env::var("GITHUB_SHA")
        .or_else(|_| std::env::var("GIT_HASH"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn hash_file(path: &std::path::Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_hex(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_id_is_deterministic() {
        let indicators_a = vec![Indicator("b".into()), Indicator("a".into())];
        let indicators_b = vec![Indicator("a".into()), Indicator("b".into())];
        let id_a = stable_signal_id(
            &SignalType::TyposquatDomain,
            "example.com",
            "ev1",
            &indicators_a,
        );
        let id_b = stable_signal_id(
            &SignalType::TyposquatDomain,
            "example.com",
            "ev1",
            &indicators_b,
        );
        assert_eq!(id_a, id_b);
    }
}
