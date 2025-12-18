use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use strsim::levenshtein;
use tracing::warn;

use crate::core::{
    error::FalconError,
    scope::ClientScope,
    signal::{Evidence, Severity, Signal, SignalType},
};

/// Generate typosquat candidates and resolve them; emit signals for those that resolve.
pub async fn typosquat_signals(
    scope: &ClientScope,
    client: &Client,
) -> Result<Vec<Signal>, FalconError> {
    let mut signals = Vec::new();
    for domain in &scope.domains {
        let candidates = gen_typos(domain, scope.typosquat_locale.as_deref());
        for cand in candidates {
            if cand == *domain {
                continue;
            }
            let resolves = tokio::net::lookup_host((cand.as_str(), 80)).await.is_ok();
            if resolves {
                let age_days = rdap_age_days(&cand, client).await.unwrap_or(None);
                let mut confidence: u8 = 70;
                let mut severity = Severity::Medium;
                let mut note = "Typosquat domain resolves".to_string();
                let distance = levenshtein(&cand, domain);
                if let Some(weight) = scope.typosquat_distance_weight {
                    let boost = weight.saturating_sub(distance as u8);
                    if boost > 0 {
                        confidence = confidence.saturating_add(boost as u8);
                    }
                }
                if let Some(days) = age_days {
                    note = format!("Typosquat domain resolves; age {} days", days);
                    if days < 30 {
                        confidence += 15;
                    }
                    if days < 7 {
                        severity = Severity::High;
                        confidence += 10;
                    }
                }
                let evidence = Evidence {
                    source: "dns".to_string(),
                    url: Some(format!("http://{}", cand)),
                    observed_at: Utc::now(),
                    note: Some(note),
                };
                signals.push(Signal::new(
                    SignalType::TyposquatDomain,
                    domain.clone(),
                    vec![evidence],
                    confidence,
                    severity,
                    vec![
                        "typosquat".into(),
                        "brand-abuse".into(),
                        "new-domain".into(),
                    ],
                    "Investigate domain ownership; consider takedown.",
                    format!("typo:{}->{}", domain, cand),
                ));
            }
        }
    }
    Ok(signals)
}

fn gen_typos(domain: &str, locale: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let base = domain.replace('.', "");
    out.push(format!("{}-secure.com", base));
    out.push(format!("{}-login.com", base));
    out.push(format!("{}-support.com", base));
    if domain.starts_with("www.") {
        out.push(domain.trim_start_matches("www.").to_string());
    }
    if let Some((sld, tld)) = domain.rsplit_once('.') {
        out.push(format!("{}-{}.{}", sld, "auth", tld));
        out.push(format!("{}{}.{}", sld, "secure", tld));
        out.push(format!("{}-{}.{}", sld, "verify", tld));
        out.push(format!("{}-{}.{}", sld, "update", tld));

        // single-character substitution and omission
        let chars: Vec<char> = sld.chars().collect();
        for i in 0..chars.len() {
            // omission
            let mut omit = chars.clone();
            omit.remove(i);
            let omit_sld: String = omit.into_iter().collect();
            out.push(format!("{}.{}", omit_sld, tld));

            // substitution with common homoglyphs
            let sub_chars = ['0', '1', 'l', 'i', 'o'];
            for rep in sub_chars.iter() {
                let mut subs = chars.clone();
                subs[i] = *rep;
                let subs_sld: String = subs.into_iter().collect();
                out.push(format!("{}.{}", subs_sld, tld));
            }
        }
        // adjacent swap
        for i in 0..chars.len().saturating_sub(1) {
            let mut swap = chars.clone();
            swap.swap(i, i + 1);
            let swap_sld: String = swap.into_iter().collect();
            out.push(format!("{}.{}", swap_sld, tld));
        }

        let keyboard_map = keyboard_map(locale);
        for i in 0..chars.len() {
            for (key, adj) in keyboard_map.iter() {
                if chars[i].to_ascii_lowercase() == *key {
                    for rep in adj {
                        let mut subs = chars.clone();
                        subs[i] = *rep;
                        let subs_sld: String = subs.iter().collect();
                        out.push(format!("{}.{}", subs_sld, tld));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn keyboard_map(locale: Option<&str>) -> Vec<(char, Vec<char>)> {
    // Default US layout; simplified alternates for es/fr only for nearby vowels/consonants.
    let us = vec![
        ('q', vec!['w', 'a']),
        ('w', vec!['q', 'e', 's']),
        ('e', vec!['w', 'r', 'd']),
        ('r', vec!['e', 't', 'f']),
        ('t', vec!['r', 'y', 'g']),
        ('y', vec!['t', 'u', 'h']),
        ('u', vec!['y', 'i', 'j']),
        ('i', vec!['u', 'o', 'k']),
        ('o', vec!['i', 'p', 'l']),
        ('p', vec!['o']),
        ('a', vec!['q', 's', 'z']),
        ('s', vec!['a', 'w', 'd', 'x']),
        ('d', vec!['s', 'e', 'f', 'c']),
        ('f', vec!['d', 'r', 'g', 'v']),
        ('g', vec!['f', 't', 'h', 'b']),
        ('h', vec!['g', 'y', 'j', 'n']),
        ('j', vec!['h', 'u', 'k', 'm']),
        ('k', vec!['j', 'i', 'l']),
        ('l', vec!['k', 'o']),
        ('z', vec!['a', 'x']),
        ('x', vec!['z', 's', 'c']),
        ('c', vec!['x', 'd', 'v']),
        ('v', vec!['c', 'f', 'b']),
        ('b', vec!['v', 'g', 'n']),
        ('n', vec!['b', 'h', 'm']),
        ('m', vec!['n', 'j']),
    ];
    match locale.unwrap_or("us") {
        "es" => us.into_iter().map(|(k, v)| (k, v)).collect(),
        "fr" => us
            .into_iter()
            .map(|(k, mut v)| {
                if k == 'a' {
                    v.push('q'); // AZERTY neighbors
                }
                if k == 'z' {
                    v.push('w');
                }
                (k, v)
            })
            .collect(),
        _ => us,
    }
}

/// Query CT logs via crt.sh for new certificates matching client domains.
pub async fn ct_log_signals(
    scope: &ClientScope,
    client: &Client,
) -> Result<Vec<Signal>, FalconError> {
    let mut signals = Vec::new();
    for domain in &scope.domains {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let resp = client.get(&url).send().await.map_err(FalconError::from)?;
        if !resp.status().is_success() {
            continue;
        }
        let text = resp.text().await.map_err(FalconError::from)?;
        let entries: Vec<CrtEntry> = serde_json::from_str(&text).unwrap_or_default();
        for entry in entries.iter().take(25) {
            let names = entry.name_value.replace('\n', ",");
            let evidence = Evidence {
                source: "crt.sh".to_string(),
                url: Some(url.clone()),
                observed_at: Utc::now(),
                note: Some(format!("Names: {}", names)),
            };
            signals.push(Signal::new(
                SignalType::NewCert,
                domain.clone(),
                vec![evidence],
                60,
                Severity::Medium,
                vec!["certificate".into()],
                "Validate certificate issuance; check if domain is authorized.",
                format!("crt:{}:{}", domain, entry.entry_timestamp),
            ));
        }
    }
    Ok(signals)
}

#[derive(Debug, Deserialize)]
struct CrtEntry {
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    entry_timestamp: String,
}

async fn rdap_age_days(domain: &str, client: &Client) -> Result<Option<i64>, FalconError> {
    let url = format!("https://rdap.org/domain/{}", domain);
    let resp = client.get(url).send().await.map_err(FalconError::from)?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let json: serde_json::Value = resp.json().await.map_err(FalconError::from)?;
    if let Some(events) = json.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            if ev.get("eventAction").and_then(|a| a.as_str()) == Some("registration") {
                if let Some(date_str) = ev.get("eventDate").and_then(|d| d.as_str()) {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
                        let days = (Utc::now() - dt.with_timezone(&Utc)).num_days();
                        return Ok(Some(days));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Leak keyword search against GitHub code search (token optional). Respects rate limits.
pub async fn leak_keyword_signals(
    scope: &ClientScope,
    client: &Client,
    github_token: Option<&str>,
) -> Result<Vec<Signal>, FalconError> {
    let mut signals = Vec::new();
    if scope.watchlists.is_empty() {
        return Ok(signals);
    }

    for term in &scope.watchlists {
        tokio::time::sleep(std::time::Duration::from_millis(
            scope.rate_limits.github_min_interval_ms,
        ))
        .await;
        let url = format!("https://api.github.com/search/code?q={term}&per_page=5");
        let mut req = client.get(&url);
        if let Some(tok) = github_token {
            req = req.bearer_auth(tok);
        }
        let resp = req.send().await.map_err(FalconError::from)?;
        if resp.status().as_u16() == 403 {
            warn!("GitHub rate limit or auth issue while searching '{}'", term);
            continue;
        }
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("GitHub rate limited on '{}'", term);
            continue;
        }
        if !resp.status().is_success() {
            continue;
        }
        let body = resp.text().await.map_err(FalconError::from)?;
        let parsed: GitHubSearch = serde_json::from_str(&body).unwrap_or_default();
        for item in parsed.items {
            let evidence = Evidence {
                source: "github-code".to_string(),
                url: Some(item.html_url.clone()),
                observed_at: Utc::now(),
                note: Some(format!("repo: {}", item.repository.full_name)),
            };
            signals.push(Signal::new(
                SignalType::LeakIndicator,
                term.clone(),
                vec![evidence],
                60,
                Severity::Medium,
                vec!["code-leak".into(), "keyword".into()],
                "Review and revoke exposed secrets; notify repo owner.",
                format!("gh-leak:{}:{}", term, item.sha),
            ));
        }
    }
    Ok(signals)
}

#[derive(Debug, Deserialize, Default)]
struct GitHubSearch {
    #[serde(default)]
    items: Vec<GitHubItem>,
}

#[derive(Debug, Deserialize, Default)]
struct GitHubItem {
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    sha: String,
    #[serde(default)]
    repository: GitHubRepo,
}

#[derive(Debug, Deserialize, Default)]
struct GitHubRepo {
    #[serde(default)]
    full_name: String,
}

/// Paste source search (psbdmp-like) with token and rate limit backoff.
pub async fn paste_signals(
    scope: &ClientScope,
    client: &Client,
    paste_token: Option<&str>,
    github_token: Option<&str>,
) -> Result<Vec<Signal>, FalconError> {
    let mut signals = Vec::new();
    let mut terms = scope.watchlists.clone();
    terms.extend(scope.brand_terms.clone());
    if terms.is_empty() {
        return Ok(signals);
    }

    for term in terms {
        let url = format!("https://psbdmp.ws/api/v3/search/{term}");
        let mut attempt = 0;
        let resp = loop {
            attempt += 1;
            tokio::time::sleep(std::time::Duration::from_millis(
                scope.rate_limits.paste_min_interval_ms,
            ))
            .await;
            let mut req = client.get(&url);
            if let Some(tok) = paste_token {
                req = req.header("Authorization", format!("Bearer {}", tok));
            }
            let res = req.send().await.map_err(FalconError::from)?;
            if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                let backoff = 500 * attempt;
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                continue;
            }
            break res;
        };

        if !resp.status().is_success() {
            warn!("paste search non-success for '{}': {}", term, resp.status());
            continue;
        }
        let text = resp.text().await.map_err(FalconError::from)?;
        let parsed: PasteSearch = serde_json::from_str(&text).unwrap_or_default();
        for hit in parsed.data.into_iter().take(5) {
            let evidence = Evidence {
                source: "paste-intel".to_string(),
                url: Some(format!("https://psbdmp.ws/{}", hit.id)),
                observed_at: Utc::now(),
                note: Some(format!("size: {} bytes; tags: {}", hit.size, hit.tags)),
            };
            signals.push(Signal::new(
                SignalType::LeakIndicator,
                term.clone(),
                vec![evidence],
                70,
                Severity::High,
                vec!["paste".into(), "leak".into()],
                "Validate exposure and rotate credentials; pursue takedown.",
                format!("paste:{}:{}", term, hit.id),
            ));
        }

        // fallback gist search if paste found nothing
        if signals.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(
                scope.rate_limits.github_min_interval_ms,
            ))
            .await;
            let gist_url =
                format!("https://api.github.com/search/code?q={term}+is:gist&per_page=3");
            let mut req = client.get(&gist_url);
            if let Some(tok) = github_token {
                req = req.bearer_auth(tok);
            }
            let resp = req.send().await.map_err(FalconError::from)?;
            if resp.status().is_success() {
                let body = resp.text().await.map_err(FalconError::from)?;
                let parsed: GitHubSearch = serde_json::from_str(&body).unwrap_or_default();
                for item in parsed.items.into_iter().take(3) {
                    let evidence = Evidence {
                        source: "gist-intel".to_string(),
                        url: Some(item.html_url.clone()),
                        observed_at: Utc::now(),
                        note: Some(format!("repo: {}", item.repository.full_name)),
                    };
                    signals.push(Signal::new(
                        SignalType::LeakIndicator,
                        term.clone(),
                        vec![evidence],
                        55,
                        Severity::Medium,
                        vec!["gist".into(), "leak".into()],
                        "Inspect gist content; remove secrets if exposed.",
                        format!("gist:{}:{}", term, item.sha),
                    ));
                }
            }
        }
    }

    Ok(signals)
}

#[derive(Debug, Deserialize, Default)]
struct PasteSearch {
    #[serde(default)]
    data: Vec<PasteHit>,
}

#[derive(Debug, Deserialize, Default)]
struct PasteHit {
    #[serde(default)]
    id: String,
    #[serde(default)]
    size: i64,
    #[serde(default)]
    tags: String,
}
