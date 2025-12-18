use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::core::error::FalconError;
use crate::core::signal::Signal;

pub struct SignalStore {
    conn: Connection,
}

impl SignalStore {
    pub fn new(path: &Path) -> Result<Self, FalconError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| FalconError::Db(e.to_string()))?;
        }
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), FalconError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS signals(
                fingerprint TEXT PRIMARY KEY,
                signal_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                tags TEXT,
                recommended_action TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                data TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// Upsert signals; returns only those that are new (not previously stored).
    pub fn upsert_signals(&mut self, signals: &[Signal]) -> Result<Vec<Signal>, FalconError> {
        let tx = self.conn.transaction()?;
        let mut new_items = Vec::new();
        for sig in signals {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT fingerprint FROM signals WHERE fingerprint = ?1",
                    params![sig.fingerprint],
                    |row| row.get(0),
                )
                .optional()?;

            let data = serde_json::to_string(sig).map_err(|_| FalconError::Unknown)?;
            if existing.is_some() {
                tx.execute(
                    "UPDATE signals
                     SET signal_type=?1, subject=?2, severity=?3, confidence=?4, tags=?5,
                         recommended_action=?6, last_seen=?7, data=?8
                     WHERE fingerprint=?9",
                    params![
                        format!("{:?}", sig.signal_type),
                        sig.subject,
                        format!("{:?}", sig.severity),
                        sig.confidence as i64,
                        sig.tags.join(","),
                        sig.recommended_action,
                        sig.last_seen.to_rfc3339(),
                        data,
                        sig.fingerprint
                    ],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO signals
                     (fingerprint, signal_type, subject, severity, confidence, tags, recommended_action,
                      first_seen, last_seen, data)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        sig.fingerprint,
                        format!("{:?}", sig.signal_type),
                        sig.subject,
                        format!("{:?}", sig.severity),
                        sig.confidence as i64,
                        sig.tags.join(","),
                        sig.recommended_action,
                        sig.first_seen.to_rfc3339(),
                        sig.last_seen.to_rfc3339(),
                        data
                    ],
                )?;
                new_items.push(sig.clone());
            }
        }
        tx.commit()?;
        Ok(new_items)
    }

    pub fn fetch_since(&self, since: DateTime<Utc>) -> Result<Vec<Signal>, FalconError> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM signals WHERE last_seen >= ?1 ORDER BY last_seen DESC")?;
        let rows = stmt
            .query_map(params![since.to_rfc3339()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        let mut out = Vec::new();
        for json in rows {
            if let Ok(sig) = serde_json::from_str::<Signal>(&json) {
                out.push(sig);
            }
        }
        Ok(out)
    }
}
