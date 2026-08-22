use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::event::DetectionEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub id: String,
    pub timestamp_unix: u64,
    pub module: String,
    pub severity: String,
    pub summary: String,
    pub detail: String,
    pub pid: Option<i32>,
    pub affected_paths: Vec<String>,
    pub action_taken: bool,
}

impl From<&DetectionEvent> for HistoryRecord {
    fn from(evt: &DetectionEvent) -> Self {
        Self {
            id: evt.id.clone(),
            timestamp_unix: evt.timestamp_unix,
            module: evt.module.to_string(),
            severity: evt.severity.to_string(),
            summary: evt.summary.clone(),
            detail: evt.detail.clone(),
            pid: evt.pid,
            affected_paths: evt.affected_paths.iter().map(|p| p.display().to_string()).collect(),
            action_taken: evt.action_taken,
        }
    }
}

/// Append-only JSONL log of every detection, across every module - the
/// record a future GUI reads to answer "what has Warden done" (a
/// notification's click action jumping to one incident by `id`, a
/// dashboard listing recent activity). Same format as the per-module
/// quarantine manifests (`quarantine::Quarantine`), just unified across
/// modules instead of scoped to one. Shared by every Warden binary
/// (`warden`, `warden-exec`, `warden-network`) - each opens the same
/// path independently and appends, rather than routing every module's
/// events through a single process, since the eBPF modules already run
/// as their own root processes for kernel-attach reasons unrelated to
/// history. Concurrent multi-process appends are safe: each record is
/// written as one `write_all` call to an `O_APPEND` fd, and Linux
/// guarantees that a single `write()` to an append-mode fd is atomic
/// with respect to other writers on the same local file.
///
/// Deliberately a plain JSONL file, not SQLite or another embedded
/// database: a workstation's realistic detection volume never needs
/// indexed queries, and appending a line is simpler to reason about and
/// to recover from a torn write than a database file would be.
#[derive(Clone)]
pub struct HistoryStore {
    path: PathBuf,
}

impl HistoryStore {
    /// Creates the state directory and enforces `0700` on it, never
    /// trusting the umask. The GUI's `History` reads go through the
    /// control socket (already uid-gated), not a direct file read, so
    /// there's no reason for this file or its directory to be readable
    /// by any account other than root - a review found both were left at
    /// the default `022`-umask mode (`0755`/`0644`) by every code path
    /// that creates them, silently undermining the socket's own uid gate
    /// for any other local account on a shared machine.
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(|| format!("setting permissions on {}", parent.display()))?;
        }
        Ok(Self { path: path.to_path_buf() })
    }

    pub fn record(&self, evt: &DetectionEvent) -> Result<()> {
        let record = HistoryRecord::from(evt);
        let line = format!("{}\n", serde_json::to_string(&record)?);
        let mut f = OpenOptions::new().create(true).append(true).mode(0o600).open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        f.write_all(line.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// The last `limit` recorded events, oldest first. Malformed lines
    /// (e.g. a write torn by a crash mid-append) are skipped with a
    /// warning rather than failing the whole read - a future GUI asking
    /// "what happened recently" should still get everything readable.
    pub fn recent(&self, limit: usize) -> Result<Vec<HistoryRecord>> {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };

        let mut events = Vec::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<HistoryRecord>(line) {
                Ok(r) => events.push(r),
                Err(e) => warn!(error = %e, "skipping malformed history line"),
            }
        }

        let start = events.len().saturating_sub(limit);
        Ok(events.split_off(start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("warden-history-test-{name}-{}.jsonl", std::process::id()))
    }

    #[test]
    fn records_and_reads_back_events() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let store = HistoryStore::new(&path).unwrap();

        let evt = DetectionEvent::new("persistence", Severity::High, "summary", "detail");
        store.record(&evt).unwrap();

        let events = store.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, evt.id);
        assert_eq!(events[0].module, "persistence");
        assert_eq!(events[0].severity, "high");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recent_limits_and_keeps_newest_last() {
        let path = temp_path("limit");
        let _ = std::fs::remove_file(&path);
        let store = HistoryStore::new(&path).unwrap();

        for i in 0..5 {
            let evt = DetectionEvent::new("yara", Severity::Medium, format!("event {i}"), "detail");
            store.record(&evt).unwrap();
        }

        let events = store.recent(2).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "event 3");
        assert_eq!(events[1].summary, "event 4");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recent_on_missing_file_returns_empty() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        let store = HistoryStore::new(&path).unwrap();
        assert!(store.recent(10).unwrap().is_empty());
    }
}
