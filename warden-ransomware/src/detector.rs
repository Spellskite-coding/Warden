use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::RansomwareConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Too many *distinct files* high-entropy-rewritten within the time
    /// window - either by the same PID, or across PIDs in the same
    /// directory (see `Detector`'s doc comment for why both are tracked).
    Burst { affected: Vec<PathBuf> },
}

/// Tracks recent high-entropy writes two ways, both keyed on distinct
/// paths (not raw write events, so one large file written in many chunks
/// doesn't get mistaken for many files) within a rolling time window:
///
/// - **Per originating PID** (`recent_writes_by_pid`): catches "one
///   process rewrites many files as ciphertext in a few seconds", the
///   common case, and lets the response path attribute the burst to a
///   specific still-running process to stop.
/// - **Per directory, PID-agnostic** (`recent_writes_by_dir`): catches
///   the same pattern spread across many short-lived processes - e.g.
///   ransomware that `fork()`s (or shells out to a one-shot encryption
///   command) once per file specifically to keep any single PID's count
///   under the per-PID threshold. A review of this code found that
///   without this second counter, that's a trivial, complete bypass of
///   burst detection regardless of how fast or how many total files get
///   encrypted. There's no single process to attribute a directory-level
///   burst to (the responsible short-lived processes may have already
///   exited by the time this fires), so the response path can only best-
///   effort target whichever PID triggered the *triggering* write.
/// - **Globally, PID- and directory-agnostic**: closes the bypass where
///   fork-per-file combined with spreading writes across several watched
///   directories keeps every per-PID and per-directory count individually
///   under threshold. Two separate maps are used (`recent_writes_global`
///   for directories with a baseline, threshold `burst_file_count`; and
///   `recent_writes_global_unbaselined` for directories without one,
///   threshold `burst_file_count * 2`) so each is always evaluated at a
///   fixed threshold. A single shared map evaluated at different thresholds
///   depending on which process writes last produces non-deterministic
///   verdicts and incorrect PID attribution. Trade-off: writes in dirs
///   with and without baseline never cumulate across maps. With default
///   burst_file_count=15, the residual cap is 14+29=43 files on the plain
///   path and 44+89=133 on the container-format path before any global
///   counter fires.
///
/// Also tracks, per directory, whether ordinary (low-entropy) content has
/// ever been seen there. A burst of high-entropy writes only counts as
/// suspicious in a directory that used to hold plain content - otherwise a
/// directory that only ever receives already-compressed output would trip
/// the same heuristic as actual encryption.
pub struct Detector {
    burst_file_count: usize,
    /// Higher threshold for writes that match a known container-format
    /// magic byte prefix (ZIP/PDF/JPEG/...) - see
    /// `observe_container_format_write`.
    container_format_burst_file_count: usize,
    burst_window: Duration,
    require_directory_baseline: bool,
    recent_writes_by_pid: HashMap<i32, HashMap<PathBuf, Instant>>,
    recent_writes_by_dir: HashMap<PathBuf, HashMap<PathBuf, Instant>>,
    recent_writes_global: HashMap<(), HashMap<PathBuf, Instant>>,
    recent_writes_global_unbaselined: HashMap<(), HashMap<PathBuf, Instant>>,
    recent_container_format_writes_by_pid: HashMap<i32, HashMap<PathBuf, Instant>>,
    recent_container_format_writes_by_dir: HashMap<PathBuf, HashMap<PathBuf, Instant>>,
    recent_container_format_writes_global: HashMap<(), HashMap<PathBuf, Instant>>,
    recent_container_format_writes_global_unbaselined: HashMap<(), HashMap<PathBuf, Instant>>,
    directories_with_plaintext_history: HashSet<PathBuf>,
}

impl Detector {
    pub fn new(cfg: &RansomwareConfig) -> Self {
        Self {
            burst_file_count: cfg.burst_file_count,
            // A container-format-matching write isn't fully trusted (see
            // `observe_container_format_write`), just held to a visibly
            // higher bar than an outright unrecognized high-entropy
            // write - 3x is a deliberately generous margin so a genuine
            // bulk save of office documents/archives/images (a user
            // zipping a folder, an app re-saving several open documents
            // at once) stays well clear of it, while a ransomware strain
            // trying to blanket-forge every file it touches with a fake
            // signature still crosses it quickly.
            container_format_burst_file_count: cfg.burst_file_count.saturating_mul(3),
            burst_window: Duration::from_secs(cfg.burst_window_secs),
            require_directory_baseline: cfg.require_directory_baseline,
            recent_writes_by_pid: HashMap::new(),
            recent_writes_by_dir: HashMap::new(),
            recent_writes_global: HashMap::new(),
            recent_writes_global_unbaselined: HashMap::new(),
            recent_container_format_writes_by_pid: HashMap::new(),
            recent_container_format_writes_by_dir: HashMap::new(),
            recent_container_format_writes_global: HashMap::new(),
            recent_container_format_writes_global_unbaselined: HashMap::new(),
            directories_with_plaintext_history: HashSet::new(),
        }
    }

    pub fn note_plaintext_activity(&mut self, path: &Path) {
        if let Some(dir) = path.parent() {
            self.directories_with_plaintext_history.insert(dir.to_path_buf());
        }
    }

    fn has_baseline(&self, path: &Path) -> bool {
        !self.require_directory_baseline || path.parent().is_some_and(|dir| self.directories_with_plaintext_history.contains(dir))
    }

    /// Records a distinct-path hit in `map[key]`, prunes anything outside
    /// the burst window, and returns the surviving paths once the count
    /// reaches `threshold` (empty otherwise).
    fn record_and_check<K: std::hash::Hash + Eq>(
        map: &mut HashMap<K, HashMap<PathBuf, Instant>>,
        key: K,
        path: &Path,
        now: Instant,
        window: Duration,
        threshold: usize,
    ) -> Option<Vec<PathBuf>> {
        let files = map.entry(key).or_default();
        files.insert(path.to_path_buf(), now);
        files.retain(|_, &mut seen| now.duration_since(seen) <= window);
        if files.len() >= threshold {
            Some(files.keys().cloned().collect())
        } else {
            None
        }
    }

    pub fn observe_high_entropy_write(&mut self, pid: i32, path: &Path) -> Verdict {
        let now = Instant::now();
        let window = self.burst_window;
        let has_baseline = self.has_baseline(path);

        let pid_burst = Self::record_and_check(&mut self.recent_writes_by_pid, pid, path, now, window, self.burst_file_count);

        if has_baseline {
            if let Some(affected) = pid_burst {
                return Verdict::Burst { affected };
            }
            if let Some(affected) = Self::record_and_check(&mut self.recent_writes_global, (), path, now, window, self.burst_file_count) {
                return Verdict::Burst { affected };
            }
            if let Some(dir) = path.parent() {
                if let Some(affected) =
                    Self::record_and_check(&mut self.recent_writes_by_dir, dir.to_path_buf(), path, now, window, self.burst_file_count)
                {
                    return Verdict::Burst { affected };
                }
            }
        } else if let Some(affected) = Self::record_and_check(&mut self.recent_writes_global_unbaselined, (), path, now, window, self.burst_file_count.saturating_mul(2)) {
            return Verdict::Burst { affected };
        }

        Verdict::Clean
    }

    /// Same idea as `observe_high_entropy_write`, for a write that
    /// matched a known container-format magic byte prefix: not trusted
    /// outright (the prefix is trivial to forge over real ciphertext,
    /// and the exact bytes are public - see `container_formats.rs`), but
    /// held to `container_format_burst_file_count` (a higher bar) rather
    /// than counted alongside outright-unrecognized high-entropy writes.
    ///
    /// Tracks per-PID too, not just directory and global - a review found
    /// this used to be directory/global only, on the reasoning that
    /// "signature-forgery combined with fork-per-file is the realistic
    /// threat model", but that made the actual bypass *wider* than
    /// intended: a single, non-forking process forging a container-format
    /// header over every file it encrypts got a full 3x weaker detection
    /// bar than a plain high-entropy write from that same process would -
    /// not because the design meant to give single-process forgery a
    /// pass, but because the fastest, most direct signal for exactly that
    /// case (per-PID) was simply missing from this path. Restored at the
    /// same elevated threshold as the other two counters here, so a
    /// genuine bulk-save still isn't over-eagerly flagged, but a single
    /// process forging its way through many files no longer needs a
    /// hollowed-out detector to do it. Also means `files_for_pid` can now
    /// correctly attribute a container-format burst back to the process
    /// that triggered it, for response/quarantine purposes.
    pub fn observe_container_format_write(&mut self, pid: i32, path: &Path) -> Verdict {
        let now = Instant::now();
        let window = self.burst_window;
        let threshold = self.container_format_burst_file_count;
        let has_baseline = self.has_baseline(path);

        let pid_burst = Self::record_and_check(&mut self.recent_container_format_writes_by_pid, pid, path, now, window, threshold);

        if has_baseline {
            if let Some(affected) = pid_burst {
                return Verdict::Burst { affected };
            }
            if let Some(affected) = Self::record_and_check(&mut self.recent_container_format_writes_global, (), path, now, window, threshold) {
                return Verdict::Burst { affected };
            }
            if let Some(dir) = path.parent() {
                if let Some(affected) =
                    Self::record_and_check(&mut self.recent_container_format_writes_by_dir, dir.to_path_buf(), path, now, window, threshold)
                {
                    return Verdict::Burst { affected };
                }
            }
        } else if let Some(affected) = Self::record_and_check(&mut self.recent_container_format_writes_global_unbaselined, (), path, now, window, threshold.saturating_mul(2)) {
            return Verdict::Burst { affected };
        }

        Verdict::Clean
    }

    /// Distinct files recently touched by `pid`, for quarantine purposes
    /// (e.g. bundling them alongside a honeypot hit from the same
    /// process). Merges both the plain-high-entropy and container-format
    /// per-PID maps, so a burst caught only via forged-signature writes
    /// is still attributed correctly.
    pub fn files_for_pid(&self, pid: i32) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self.recent_writes_by_pid.get(&pid).map(|m| m.keys().cloned().collect()).unwrap_or_default();
        if let Some(m) = self.recent_container_format_writes_by_pid.get(&pid) {
            files.extend(m.keys().cloned());
        }
        files
    }

    pub fn forget(&mut self, pid: i32) {
        self.recent_writes_by_pid.remove(&pid);
        self.recent_container_format_writes_by_pid.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector_with_threshold(burst_file_count: usize) -> Detector {
        let cfg = RansomwareConfig { burst_file_count, require_directory_baseline: false, ..RansomwareConfig::default() };
        Detector::new(&cfg)
    }

    #[test]
    fn single_pid_single_dir_burst_is_still_caught() {
        let mut d = detector_with_threshold(15);
        let mut verdict = Verdict::Clean;
        for i in 0..15 {
            verdict = d.observe_high_entropy_write(1234, Path::new(&format!("/home/test/Documents/f{i}.bin")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "15 files from one pid in one dir must still trigger");
    }

    /// Regression test for the red-team-confirmed bypass: fork-per-file
    /// (one PID per write) *combined with* spreading those writes across
    /// several watched directories, each individually staying under
    /// `burst_file_count`. Reproduces the exact live finding - 48 files,
    /// 6 directories, 8 per directory, one PID per file - which the
    /// per-PID and per-directory counters alone let through completely.
    #[test]
    fn fork_per_file_spread_across_directories_is_caught_by_the_global_counter() {
        let mut d = detector_with_threshold(15);
        let dirs = ["Documents", "Bureau", "Téléchargements", "Images", "Vidéos", "Musique"];
        let mut verdict = Verdict::Clean;
        let mut pid = 10_000;
        'outer: for dir in dirs {
            for i in 0..8 {
                pid += 1; // a distinct short-lived process per file
                let path = PathBuf::from(format!("/home/test/{dir}/redteam_victim_{i}.bin"));
                verdict = d.observe_high_entropy_write(pid, &path);
                if matches!(verdict, Verdict::Burst { .. }) {
                    break 'outer;
                }
            }
        }
        assert!(
            matches!(verdict, Verdict::Burst { .. }),
            "48 files across 6 dirs (8 each, distinct pids) must trigger the global counter even though no per-pid or per-dir count reaches the threshold alone"
        );
    }

    #[test]
    fn low_volume_activity_spread_across_directories_stays_clean() {
        let mut d = detector_with_threshold(15);
        let dirs = ["Documents", "Bureau", "Téléchargements", "Images", "Vidéos", "Musique"];
        let mut verdict = Verdict::Clean;
        let mut pid = 20_000;
        for dir in dirs {
            for i in 0..2 {
                pid += 1;
                let path = PathBuf::from(format!("/home/test/{dir}/normal_save_{i}.bin"));
                verdict = d.observe_high_entropy_write(pid, &path);
            }
        }
        assert_eq!(verdict, Verdict::Clean, "12 total files spread thinly across 6 dirs is ordinary activity, not a burst");
    }

    #[test]
    fn global_counter_catches_burst_in_directory_with_no_baseline() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        let mut verdict = Verdict::Clean;
        for i in 0..30 {
            verdict = d.observe_high_entropy_write(1234, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }));
    }

    #[test]
    fn per_pid_alone_does_not_trigger_without_baseline() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        let mut verdict = Verdict::Clean;
        for i in 0..15 {
            verdict = d.observe_high_entropy_write(1234, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn global_counter_catches_container_format_burst_in_directory_with_no_baseline() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        let mut verdict = Verdict::Clean;
        for i in 0..90 {
            verdict = d.observe_container_format_write(1234, Path::new(&format!("/home/test/new_dir/file_{i}.zip")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }));
    }

    #[test]
    fn baselined_dir_uses_regular_global_threshold() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        d.note_plaintext_activity(Path::new("/home/test/docs/readme.txt"));
        d.note_plaintext_activity(Path::new("/home/test/desktop/note.txt"));
        // 8 files from distinct PIDs in docs/ — under per-pid and per-dir thresholds
        for i in 0..8 {
            d.observe_high_entropy_write(1000 + i, Path::new(&format!("/home/test/docs/file_{i}.enc")));
        }
        // 7 more from distinct PIDs in desktop/ — each local counter still under 15
        let mut verdict = Verdict::Clean;
        for i in 0..7 {
            verdict = d.observe_high_entropy_write(2000 + i, Path::new(&format!("/home/test/desktop/file_{i}.enc")));
        }
        // global baselined map at 15 → fires
        assert!(matches!(verdict, Verdict::Burst { .. }));
    }

    #[test]
    fn mixed_baseline_and_no_baseline_writes_use_separate_maps() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        d.note_plaintext_activity(Path::new("/home/test/docs/readme.txt"));
        // 29 unbaselined writes — just below the 2x=30 threshold
        for i in 0..29i32 {
            d.observe_high_entropy_write(9000 + i, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        // 14 baselined writes — just below the 1x=15 threshold
        let mut verdict = Verdict::Clean;
        for i in 0..14i32 {
            verdict = d.observe_high_entropy_write(8000 + i, Path::new(&format!("/home/test/docs/file_{i}.enc")));
        }
        // maps are separate: neither threshold reached
        assert_eq!(verdict, Verdict::Clean);
    }

    /// Regression test for the finding that `observe_container_format_write`
    /// tracked no per-PID counter at all - a single, non-forking process
    /// forging container-format signatures got a strictly weaker (dir/
    /// global only) detection bar than the equivalent plain high-entropy
    /// write would, and `files_for_pid` could never attribute the burst
    /// back to it. A single PID hitting the threshold must both trigger a
    /// burst verdict AND have those files show up in `files_for_pid`.
    #[test]
    fn container_format_burst_from_a_single_pid_is_attributed_to_that_pid() {
        let mut d = detector_with_threshold(15); // container_format_burst_file_count = 45
        let pid = 555;
        let mut verdict = Verdict::Clean;
        for i in 0..45 {
            verdict = d.observe_container_format_write(pid, &PathBuf::from(format!("/home/test/Documents/f{i}.zip")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "45 container-format writes from one pid must trigger a burst");
        assert_eq!(d.files_for_pid(pid).len(), 45, "the burst's files must be attributable back to the triggering pid");
    }
}