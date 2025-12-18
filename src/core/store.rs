use std::path::Path;

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use crate::core::time::now_utc;
use crate::core::types::{Finding, Manifest, Signal, TrendBucket, TrendReport};

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn default_path() -> std::path::PathBuf {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.join("data").join("falcon.db")
    }

    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              started_at TEXT NOT NULL,
              ended_at TEXT NOT NULL,
              scope_hash TEXT NOT NULL,
              config_hash TEXT NOT NULL,
              manifest_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS signals (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              dedupe_key TEXT NOT NULL,
              signal_type TEXT NOT NULL,
              subject TEXT NOT NULL,
              source TEXT NOT NULL,
              evidence_ref TEXT NOT NULL,
              confidence INTEGER NOT NULL,
              severity TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_signals_run ON signals(run_id);
            CREATE INDEX IF NOT EXISTS idx_signals_dedupe ON signals(dedupe_key);

            CREATE TABLE IF NOT EXISTS findings (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              severity TEXT NOT NULL,
              confidence INTEGER NOT NULL,
              rationale TEXT NOT NULL,
              data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            ",
        )?;
        Ok(())
    }

    pub fn store_run(
        &mut self,
        run_id: &str,
        manifest: &Manifest,
        signals: &[Signal],
        findings: &[Finding],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        let manifest_json = serde_json::to_string(manifest)?;
        tx.execute(
            "INSERT OR REPLACE INTO runs (run_id, started_at, ended_at, scope_hash, config_hash, manifest_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id,
                manifest.run_window_start.to_rfc3339(),
                manifest.run_window_end.to_rfc3339(),
                manifest.scope_hash,
                manifest.config_hash,
                manifest_json
            ],
        )?;

        for sig in signals {
            let data_json = serde_json::to_string(sig)?;
            tx.execute(
                "INSERT OR REPLACE INTO signals
                 (id, run_id, dedupe_key, signal_type, subject, source, evidence_ref, confidence, severity, timestamp, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    sig.id,
                    run_id,
                    sig.dedupe_key,
                    format!("{:?}", sig.signal_type),
                    sig.subject,
                    sig.source,
                    sig.evidence_ref,
                    sig.confidence as i64,
                    format!("{:?}", sig.severity),
                    sig.timestamp.to_rfc3339(),
                    data_json
                ],
            )?;
        }

        for f in findings {
            let data_json = serde_json::to_string(f)?;
            tx.execute(
                "INSERT OR REPLACE INTO findings
                 (id, run_id, severity, confidence, rationale, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    f.id,
                    run_id,
                    format!("{:?}", f.severity),
                    f.confidence as i64,
                    f.rationale,
                    data_json
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn purge_older_than(&mut self, retention_days: u32) -> Result<()> {
        if retention_days == 0 {
            return Ok(());
        }
        let cutoff = now_utc() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM signals WHERE run_id IN (SELECT run_id FROM runs WHERE started_at < ?1)",
            params![cutoff_str],
        )?;
        tx.execute(
            "DELETE FROM findings WHERE run_id IN (SELECT run_id FROM runs WHERE started_at < ?1)",
            params![cutoff_str],
        )?;
        tx.execute(
            "DELETE FROM runs WHERE started_at < ?1",
            params![cutoff_str],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn latest_signals(&self) -> Result<Vec<Signal>> {
        let run_id: Option<String> = self
            .conn
            .query_row(
                "SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let Some(run_id) = run_id else {
            return Ok(vec![]);
        };

        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM signals WHERE run_id = ?1")?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            let sig: Signal = serde_json::from_str(&json)?;
            out.push(sig);
        }
        Ok(out)
    }

    pub fn latest_findings(&self) -> Result<Vec<Finding>> {
        let run_id: Option<String> = self
            .conn
            .query_row(
                "SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let Some(run_id) = run_id else {
            return Ok(vec![]);
        };

        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM findings WHERE run_id = ?1")?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            let finding: Finding = serde_json::from_str(&json)?;
            out.push(finding);
        }
        Ok(out)
    }

    pub fn trend_report(&self, window: chrono::Duration) -> Result<TrendReport> {
        let end = now_utc();
        let start = end - window;
        let prev_end = start;
        let prev_start = start - window;

        let current = self.signals_in_window(start, end)?;
        let previous = self.signals_in_window(prev_start, prev_end)?;
        let all = self.all_signals()?;

        let by_type = build_trend_buckets(&current, &previous, &all, start, |s| {
            format!("{:?}", s.signal_type)
        });
        let by_subject =
            build_trend_buckets(&current, &previous, &all, start, |s| s.subject.clone());
        let by_dedupe =
            build_trend_buckets(&current, &previous, &all, start, |s| s.dedupe_key.clone());

        let summary = trend_summary(&by_type, window.num_days());

        Ok(TrendReport {
            window_start: start,
            window_end: end,
            by_signal_type: by_type,
            by_subject: by_subject,
            by_dedupe_key: by_dedupe,
            summary,
        })
    }

    fn signals_in_window(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Signal>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM signals WHERE timestamp >= ?1 AND timestamp < ?2")?;
        let rows = stmt.query_map(params![start.to_rfc3339(), end.to_rfc3339()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            let sig: Signal = serde_json::from_str(&json)?;
            out.push(sig);
        }
        Ok(out)
    }

    fn all_signals(&self) -> Result<Vec<Signal>> {
        let mut stmt = self.conn.prepare("SELECT data_json FROM signals")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            let sig: Signal = serde_json::from_str(&json)?;
            out.push(sig);
        }
        Ok(out)
    }
}

fn build_trend_buckets<F>(
    current: &[Signal],
    previous: &[Signal],
    all: &[Signal],
    window_start: chrono::DateTime<chrono::Utc>,
    key_fn: F,
) -> Vec<TrendBucket>
where
    F: Fn(&Signal) -> String,
{
    let mut current_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut prev_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut first_seen: std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>> =
        std::collections::BTreeMap::new();
    let mut last_seen: std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>> =
        std::collections::BTreeMap::new();

    for sig in current {
        let key = key_fn(sig);
        *current_counts.entry(key).or_insert(0) += 1;
    }
    for sig in previous {
        let key = key_fn(sig);
        *prev_counts.entry(key).or_insert(0) += 1;
    }
    for sig in all {
        let key = key_fn(sig);
        first_seen
            .entry(key.clone())
            .and_modify(|ts| {
                if sig.timestamp < *ts {
                    *ts = sig.timestamp;
                }
            })
            .or_insert(sig.timestamp);
        last_seen
            .entry(key)
            .and_modify(|ts| {
                if sig.timestamp > *ts {
                    *ts = sig.timestamp;
                }
            })
            .or_insert(sig.timestamp);
    }

    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    keys.extend(current_counts.keys().cloned());
    keys.extend(prev_counts.keys().cloned());

    let mut buckets = Vec::new();
    for key in keys {
        let count = *current_counts.get(&key).unwrap_or(&0);
        let prev_count = *prev_counts.get(&key).unwrap_or(&0);
        let delta = count as i64 - prev_count as i64;
        let first = first_seen.get(&key).cloned();
        let last = last_seen.get(&key).cloned();
        let first_seen_in_window = first.map(|ts| ts >= window_start).unwrap_or(false);
        buckets.push(TrendBucket {
            key,
            count,
            prev_count,
            delta,
            first_seen: first,
            last_seen: last,
            first_seen_in_window,
        });
    }

    buckets.sort_by(|a, b| a.key.cmp(&b.key));
    buckets
}

fn trend_summary(by_type: &[TrendBucket], window_days: i64) -> Vec<String> {
    let mut summary = Vec::new();
    if by_type.is_empty() {
        summary.push(format!("No activity in the last {} days.", window_days));
        return summary;
    }
    for bucket in by_type {
        if bucket.count == 0 {
            continue;
        }
        if bucket.prev_count == 0 && bucket.count > 0 {
            summary.push(format!(
                "{} new {} signals in the last {} days.",
                bucket.count, bucket.key, window_days
            ));
        } else if bucket.delta > 0 {
            summary.push(format!(
                "{} {} signals ({} increase) in the last {} days.",
                bucket.count, bucket.key, bucket.delta, window_days
            ));
        } else if bucket.delta < 0 {
            summary.push(format!(
                "{} {} signals ({} decrease) in the last {} days.",
                bucket.count,
                bucket.key,
                bucket.delta.abs(),
                window_days
            ));
        } else {
            summary.push(format!(
                "{} {} signals in the last {} days.",
                bucket.count, bucket.key, window_days
            ));
        }
    }
    if summary.is_empty() {
        summary.push(format!("No new activity in the last {} days.", window_days));
    }
    summary
}
