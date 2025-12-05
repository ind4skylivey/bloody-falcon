use std::fmt;

use chrono::Local;

use crate::core::engine::ReconResult;

#[derive(Clone)]
pub struct Target {
    pub id: String,
    pub status: Status,
    pub hits: usize,
    pub emails: Vec<String>,
    pub platforms: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub enum Status {
    Scanning,
    Found,
    Empty,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Scanning => write!(f, "🦅 SCANNING"),
            Status::Found => write!(f, "✅ HIT"),
            Status::Empty => write!(f, "❌ EMPTY"),
        }
    }
}

pub struct App {
    pub targets: Vec<Target>,
    pub current_target: usize,
    pub input: String,
    pub logs: Vec<String>,
    pub scanning: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            targets: vec![],
            current_target: 0,
            input: String::new(),
            logs: vec![
                "[SYSTEM] BLOODY-FALCON v1.0 BOOT".to_string(),
                "[SYSTEM] RECON MODULES LOADED".to_string(),
                "[SYSTEM] TERMINAL MODE: ACTIVE".to_string(),
                "[SYSTEM] ENTER TARGET IDENTIFIER".to_string(),
            ],
            scanning: false,
        }
    }

    pub fn add_target(&mut self, id: String) {
        self.targets.push(Target {
            id: id.clone(),
            status: Status::Empty,
            hits: 0,
            emails: vec![],
            platforms: vec![],
        });
        self.log(format!("[+] Target added: {}", id));
    }

    /// Marks the current target as scanning and returns (index, id).
    pub fn start_scan(&mut self) -> Option<(usize, String)> {
        if self.targets.is_empty() {
            return None;
        }
        let idx = self.current_target.min(self.targets.len() - 1);
        let target_id = {
            let target = &mut self.targets[idx];
            target.status = Status::Scanning;
            target.id.clone()
        };
        self.scanning = true;
        self.log(format!(
            "🦅 SCANNING {} across 348 platforms...",
            target_id
        ));
        Some((idx, target_id))
    }

    pub fn complete_scan(&mut self, idx: usize, outcome: ReconResult) {
        if let Some(target) = self.targets.get_mut(idx) {
            target.status = Status::Found;
            target.hits = outcome.hits;
            target.emails.clear();
            target.platforms = outcome.platforms;
            let id = target.id.clone();
            let hits = target.hits;
            self.log(format!("✅ {} - {} hits found!", id, hits));
        }
        self.scanning = false;
    }

    pub fn fail_scan(&mut self, idx: usize, err: &str) {
        if let Some(target) = self.targets.get_mut(idx) {
            let id = target.id.clone();
            target.status = Status::Empty;
            self.log(format!("⚠️ Scan failed on {}: {}", id, err));
        } else {
            self.log(format!("⚠️ Scan failed: {}", err));
        }
        self.scanning = false;
    }

    pub fn next_target(&mut self) {
        self.current_target = (self.current_target + 1) % self.targets.len().max(1);
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs
            .push(format!("[{}] {}", Local::now().format("%H:%M:%S"), msg.into()));
        if self.logs.len() > 10 {
            self.logs.remove(0);
        }
    }
}
