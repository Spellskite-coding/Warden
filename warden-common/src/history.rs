use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

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
/// Once `history.jsonl` exceeds this size, `record` rotates it down to
/// the newest records that fit in half of this (see `rotate`'s doc
/// comment for why half, and why size rather than a fixed line count is
/// what's actually bounded). A workstation's realistic detection volume
/// (this file's own module doc comment) should almost never reach this
/// in practice, but nothing previously bounded it: a noisy machine
/// (frequent YARA false positives, a misconfigured monitor-mode
/// deployment logging routine activity) could grow this file
/// indefinitely, and `recent()` re-reads and re-parses the entire file
/// on every call - a GUI dashboard open in the background polling status
/// would make that cost scale with all-time history, not with what it
/// actually displays.
const HISTORY_ROTATE_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// A secondary cap on how many of the newest records survive a rotation,
/// alongside the byte-size target - see `rotate`. Comfortably above any
/// `recent(limit)` call this codebase makes (the GUI never asks for more
/// than a few hundred), so this cap alone never discards anything a
/// normal read would have returned anyway; it only bites when records
/// are unusually small and numerous.
const HISTORY_ROTATE_KEEP_LINES: usize = 5_000;

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

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        p.set_extension("jsonl.lock");
        p
    }

    /// Takes an exclusive cross-process lock, matching `Quarantine`'s
    /// `flock`-based manifest locking (same reasoning: multiple
    /// independent binaries - `warden`, `warden-exec`, `warden-network` -
    /// each open this same path themselves and append to it). Plain
    /// `O_APPEND` alone is enough to make individual appends atomic with
    /// respect to each other, but `record`'s rotation step (below) reads
    /// the whole file and replaces it via `rename` - without a lock
    /// serializing that against a concurrent append from a *different*
    /// process, that other process could still be holding an fd open to
    /// the pre-rotation inode and its next write would land on a file no
    /// longer reachable by any path, silently losing that record forever.
    fn lock(&self) -> Result<Flock<fs::File>> {
        let f = OpenOptions::new().create(true).write(true).truncate(false).mode(0o600).open(self.lock_path())?;
        Flock::lock(f, FlockArg::LockExclusive).map_err(|(_, e)| anyhow::anyhow!("locking {}: {e}", self.lock_path().display()))
    }

    pub fn record(&self, evt: &DetectionEvent) -> Result<()> {
        let _guard = self.lock().with_context(|| format!("locking {}", self.path.display()))?;

        let record = HistoryRecord::from(evt);
        let line = format!("{}\n", serde_json::to_string(&record)?);
        let mut f = OpenOptions::new().create(true).append(true).mode(0o600).open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        f.write_all(line.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        drop(f);

        if let Ok(meta) = fs::metadata(&self.path) {
            if meta.len() > HISTORY_ROTATE_MAX_BYTES {
                self.rotate()?;
            }
        }
        Ok(())
    }

    /// Keeps the newest records, bounded by BOTH `HISTORY_ROTATE_KEEP_LINES`
    /// and half of `HISTORY_ROTATE_MAX_BYTES` (whichever limit is hit
    /// first) - not just a fixed line count. A fixed line count alone
    /// doesn't actually bound the resulting file's size: an unusually
    /// large record (a Burst detection's `affected_paths` can hold
    /// thousands of entries for a widely-spread attack) could make even
    /// `HISTORY_ROTATE_KEEP_LINES` records add up to far more than
    /// `HISTORY_ROTATE_MAX_BYTES`, defeating the whole point of rotating -
    /// found by this function's own test, which pads records specifically
    /// to trigger rotation quickly and would otherwise silently produce a
    /// "rotated" file bigger than the threshold that triggered rotation
    /// in the first place. Targets half the max (not the full max) so a
    /// freshly-rotated file has real headroom to grow before the next
    /// rotation, rather than triggering one on almost every subsequent
    /// write. Always keeps at least the single newest record regardless
    /// of its size, so one outsized record can't make rotation produce an
    /// empty file. Called with the lock already held by `record`.
    /// Malformed lines are dropped the same way `recent` already
    /// tolerates them - a rotation is not the place to newly start
    /// failing over a line torn by an earlier crash.
    fn rotate(&self) -> Result<()> {
        let data = fs::read_to_string(&self.path).with_context(|| format!("reading {} for rotation", self.path.display()))?;
        let lines: Vec<&str> = data.lines().filter(|l| !l.trim().is_empty()).collect();

        let target_bytes = HISTORY_ROTATE_MAX_BYTES / 2;
        let mut kept_from = lines.len();
        let mut bytes = 0u64;
        while kept_from > 0 && lines.len() - kept_from < HISTORY_ROTATE_KEEP_LINES {
            let candidate_bytes = lines[kept_from - 1].len() as u64 + 1;
            if bytes + candidate_bytes > target_bytes && kept_from < lines.len() {
                break; // always keep at least the single newest line
            }
            bytes += candidate_bytes;
            kept_from -= 1;
        }
        let kept = &lines[kept_from..];

        let tmp_path = self.path.with_extension("jsonl.tmp");
        let mut tmp = OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        tmp.set_permissions(fs::Permissions::from_mode(0o600))?;
        for line in kept {
            writeln!(tmp, "{line}")?;
        }
        tmp.sync_all().ok();
        fs::rename(&tmp_path, &self.path).with_context(|| format!("replacing {}", self.path.display()))?;
        info!(kept = kept.len(), dropped = lines.len() - kept.len(), "rotated history.jsonl");
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

    // A bare file directly under `std::env::temp_dir()` (`/tmp`) used to be
    // returned here. `HistoryStore::new` unconditionally re-asserts `0700`
    // on its path's parent directory - the same "never trust it survived,
    // always re-apply it" pattern `Quarantine::new` uses - which is exactly
    // right for the dedicated directory a real deployment always gives it
    // (e.g. `/var/lib/warden`, owned outright by the daemon), but meant
    // these tests tried to `chmod` `/tmp` itself: harmless when `cargo
    // test` happens to run as root (owns `/tmp`), but a guaranteed
    // `EPERM` for the far more ordinary case of a non-root developer
    // running the test suite locally. Each test now gets its own
    // subdirectory it actually owns, matching `quarantine.rs`'s tests.
    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-history-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("history.jsonl")
    }

    #[test]
    fn records_and_reads_back_events() {
        let path = temp_path("roundtrip");
        let store = HistoryStore::new(&path).unwrap();

        let evt = DetectionEvent::new("persistence", Severity::High, "summary", "detail");
        store.record(&evt).unwrap();

        let events = store.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, evt.id);
        assert_eq!(events[0].module, "persistence");
        assert_eq!(events[0].severity, "high");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn recent_limits_and_keeps_newest_last() {
        let path = temp_path("limit");
        let store = HistoryStore::new(&path).unwrap();

        for i in 0..5 {
            let evt = DetectionEvent::new("yara", Severity::Medium, format!("event {i}"), "detail");
            store.record(&evt).unwrap();
        }

        let events = store.recent(2).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "event 3");
        assert_eq!(events[1].summary, "event 4");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Regression test for the finding that `history.jsonl` had nothing
    /// bounding its growth: writes padded to ~20KB each (well under the
    /// default `sample_bytes`/entropy-scan sizes, just large enough to
    /// cross `HISTORY_ROTATE_MAX_BYTES` in a bounded number of iterations
    /// so this test stays fast) until the file exceeds the rotation
    /// threshold, then confirms it actually rotated down to at most
    /// `HISTORY_ROTATE_KEEP_LINES` records, is smaller than the
    /// pre-rotation size, and is still readable afterward (the newest
    /// event survives).
    #[test]
    fn record_rotates_the_file_once_it_exceeds_the_size_threshold() {
        let path = temp_path("rotate");
        let store = HistoryStore::new(&path).unwrap();

        let padding = "x".repeat(20_000);
        let iterations = (HISTORY_ROTATE_MAX_BYTES / 20_000) as usize + 50;
        for i in 0..iterations {
            let evt = DetectionEvent::new("yara", Severity::Medium, format!("event {i}"), padding.clone());
            store.record(&evt).unwrap();
        }

        let final_size = std::fs::metadata(&path).unwrap().len();
        assert!(final_size < HISTORY_ROTATE_MAX_BYTES, "the file must have been rotated back down below the threshold, got {final_size} bytes");

        let data = std::fs::read_to_string(&path).unwrap();
        let line_count = data.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(line_count <= HISTORY_ROTATE_KEEP_LINES, "rotation must not keep more than HISTORY_ROTATE_KEEP_LINES lines, got {line_count}");

        let events = store.recent(1).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, format!("event {}", iterations - 1), "the newest record must survive rotation");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn recent_on_missing_file_returns_empty() {
        let path = temp_path("missing");
        let store = HistoryStore::new(&path).unwrap();
        assert!(store.recent(10).unwrap().is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
