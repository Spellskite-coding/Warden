use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::RansomwareConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Too many *distinct files* high-entropy-rewritten by the same PID in
    /// the time window.
    Burst { count: usize },
}

/// Tracks, per originating PID, the set of distinct files recently seen
/// with a high-entropy write, so we can catch the "many files rewritten as
/// ciphertext in a few seconds" pattern that a single event can't reveal on
/// its own. Deliberately keyed on distinct paths (not raw write events) so
/// that one large file written in many chunks doesn't get mistaken for many
/// files.
///
/// Also tracks, per directory, whether ordinary (low-entropy) content has
/// ever been seen there. A burst of high-entropy writes only counts as
/// suspicious in a directory that used to hold plain content - otherwise a
/// directory that only ever receives already-compressed output would trip
/// the same heuristic as actual encryption.
pub struct Detector {
    burst_file_count: usize,
    burst_window: Duration,
    require_directory_baseline: bool,
    recent_writes: HashMap<i32, HashMap<PathBuf, Instant>>,
    directories_with_plaintext_history: HashSet<PathBuf>,
}

impl Detector {
    pub fn new(cfg: &RansomwareConfig) -> Self {
        Self {
            burst_file_count: cfg.burst_file_count,
            burst_window: Duration::from_secs(cfg.burst_window_secs),
            require_directory_baseline: cfg.require_directory_baseline,
            recent_writes: HashMap::new(),
            directories_with_plaintext_history: HashSet::new(),
        }
    }

    pub fn note_plaintext_activity(&mut self, path: &Path) {
        if let Some(dir) = path.parent() {
            self.directories_with_plaintext_history.insert(dir.to_path_buf());
        }
    }

    pub fn observe_high_entropy_write(&mut self, pid: i32, path: &Path) -> Verdict {
        if self.require_directory_baseline {
            let has_baseline = path.parent().is_some_and(|dir| self.directories_with_plaintext_history.contains(dir));
            if !has_baseline {
                return Verdict::Clean;
            }
        }

        let now = Instant::now();
        let window = self.burst_window;
        let files = self.recent_writes.entry(pid).or_default();

        files.insert(path.to_path_buf(), now);
        files.retain(|_, &mut seen| now.duration_since(seen) <= window);

        if files.len() >= self.burst_file_count {
            Verdict::Burst { count: files.len() }
        } else {
            Verdict::Clean
        }
    }

    /// Distinct files recently touched by `pid`, for quarantine purposes.
    pub fn files_for_pid(&self, pid: i32) -> Vec<PathBuf> {
        self.recent_writes.get(&pid).map(|m| m.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn forget(&mut self, pid: i32) {
        self.recent_writes.remove(&pid);
    }
}
