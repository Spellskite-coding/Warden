use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::event::DetectionEvent;

#[derive(Serialize)]
struct HistoryRecord<'a> {
    id: &'a str,
    timestamp_unix: u64,
    module: &'a str,
    severity: String,
    summary: &'a str,
    detail: &'a str,
    pid: Option<i32>,
    affected_paths: Vec<String>,
    action_taken: bool,
}

/// Append-only JSONL log of every detection, across every module - the
/// record a future GUI reads to answer "what has Warden done" (a
/// notification's click action jumping to one incident by `id`, a
/// dashboard listing recent activity). Same format as the per-module
/// quarantine manifests (`quarantine::Quarantine`), just unified across
/// modules instead of scoped to one.
///
/// Deliberately a plain JSONL file, not SQLite or another embedded
/// database: a workstation's realistic detection volume never needs
/// indexed queries, and appending a line is simpler to reason about and
/// to recover from a torn write than a database file would be.
pub struct HistoryStore {
    path: PathBuf,
}

impl HistoryStore {
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        Ok(Self { path: path.to_path_buf() })
    }

    pub fn record(&self, evt: &DetectionEvent) -> Result<()> {
        let record = HistoryRecord {
            id: &evt.id,
            timestamp_unix: evt.timestamp_unix,
            module: evt.module,
            severity: evt.severity.to_string(),
            summary: &evt.summary,
            detail: &evt.detail,
            pid: evt.pid,
            affected_paths: evt.affected_paths.iter().map(|p| p.display().to_string()).collect(),
            action_taken: evt.action_taken,
        };

        let mut f = OpenOptions::new().create(true).append(true).open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        writeln!(f, "{}", serde_json::to_string(&record)?)?;
        Ok(())
    }
}
