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
/// - **Globally, PID- and directory-agnostic** (`recent_writes_global`):
///   a second, red-team-confirmed bypass of the two counters above -
///   fork-per-file *combined with* spreading those files across several
///   watched directories at once (e.g. `burst_file_count - 1` files each
///   in every one of the default six watch dirs) keeps every single
///   per-PID AND per-directory count individually under threshold while
///   still touching dozens of distinct files within the window.
///   Reproduced live end-to-end: 48 files across 6 directories, 8 per
///   directory, one short-lived process per file - zero detections, zero
///   quarantines. The per-directory counter alone only bounds a *single*
///   directory's count, never the sum across all of them; this third
///   counter closes that gap the same way `recent_writes_by_dir` closes
///   the per-PID one, at the same threshold - a real burst is a real
///   burst no matter how it's laundered across PIDs and directories.
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
    recent_container_format_writes_by_pid: HashMap<i32, HashMap<PathBuf, Instant>>,
    recent_container_format_writes_by_dir: HashMap<PathBuf, HashMap<PathBuf, Instant>>,
    recent_container_format_writes_global: HashMap<(), HashMap<PathBuf, Instant>>,
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
            recent_container_format_writes_by_pid: HashMap::new(),
            recent_container_format_writes_by_dir: HashMap::new(),
            recent_container_format_writes_global: HashMap::new(),
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

        // Per-PID is recorded first - before the global check returns - so
        // that files_for_pid() always includes the triggering file. If the
        // global counter fires and returns immediately below, the per-PID map
        // must already hold this write or quarantine attribution misses the
        // last file. The threshold result is captured but not acted on yet:
        // it is only returned after has_baseline() confirms enforcement applies.
        let pid_burst = Self::record_and_check(&mut self.recent_writes_by_pid, pid, path, now, window, self.burst_file_count);

        // Global counter runs unconditionally, before the has_baseline() guard.
        // A directory created after Warden starts has no plaintext history, so
        // has_baseline() returns false for it. The previous ordering placed the
        // global after the guard, making it unreachable for new directories:
        // all three counters were skipped via the early return.
        //
        // Confirmed bypass on a real install (Ubuntu 24.04, mode=enforce):
        // 20 /dev/urandom files in a freshly-created subdirectory produced
        // zero alerts and zero quarantine entries. Moving the global here
        // closes that gap: a burst is a burst regardless of whether the
        // target directory ever held plaintext.
        if let Some(affected) = Self::record_and_check(&mut self.recent_writes_global, (), path, now, window, self.burst_file_count) {
            return Verdict::Burst { affected };
        }

        // Per-directory and per-PID threshold checks remain behind the
        // has_baseline() guard: a directory that legitimately only ever
        // receives compressed or encrypted output (a backup tool's output
        // dir, a build artifact dir) should not trigger false positives.
        // The global counter above already handles the aggregate case.
        if !self.has_baseline(path) {
            return Verdict::Clean;
        }

        if let Some(affected) = pid_burst {
            return Verdict::Burst { affected };
        }

        if let Some(dir) = path.parent() {
            if let Some(affected) =
                Self::record_and_check(&mut self.recent_writes_by_dir, dir.to_path_buf(), path, now, window, self.burst_file_count)
            {
                return Verdict::Burst { affected };
            }
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

        // Same ordering as observe_high_entropy_write: per-PID recorded first
        // for attribution, global checked unconditionally before has_baseline().
        let pid_burst = Self::record_and_check(&mut self.recent_container_format_writes_by_pid, pid, path, now, window, threshold);

        if let Some(affected) = Self::record_and_check(&mut self.recent_container_format_writes_global, (), path, now, window, threshold) {
            return Verdict::Burst { affected };
        }

        if !self.has_baseline(path) {
            return Verdict::Clean;
        }

        if let Some(affected) = pid_burst {
            return Verdict::Burst { affected };
        }

        if let Some(dir) = path.parent() {
            if let Some(affected) =
                Self::record_and_check(&mut self.recent_container_format_writes_by_dir, dir.to_path_buf(), path, now, window, threshold)
            {
                return Verdict::Burst { affected };
            }
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

    /// Regression test for the live-confirmed bypass: high-entropy writes in
    /// a directory with no plaintext baseline (newly created after Warden
    /// started) were silently ignored because has_baseline() returned false
    /// and the early return skipped all three counters including the global.
    ///
    /// Reproduced on a real install: 20 /dev/urandom files in a freshly
    /// created subdirectory → zero alerts, zero quarantine entries.
    /// After the fix, the global counter fires correctly at burst_file_count.
    #[test]
    fn global_counter_catches_burst_in_directory_with_no_baseline() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        // No note_plaintext_activity calls — directory has no baseline.
        let mut verdict = Verdict::Clean;
        for i in 0..15 {
            verdict = d.observe_high_entropy_write(
                1234,
                Path::new(&format!("/home/test/new_dir_no_baseline/file_{i}.enc")),
            );
        }
        assert!(
            matches!(verdict, Verdict::Burst { .. }),
            "global counter must fire at burst_file_count even in a directory \
             with no plaintext baseline"
        );
    }

    /// Same regression for the container-format path: forging ZIP/PDF/JPEG
    /// headers over ciphertext in a new directory was equally invisible.
    #[test]
    fn global_counter_catches_container_format_burst_in_directory_with_no_baseline() {
        let cfg = RansomwareConfig { burst_file_count: 15, require_directory_baseline: true, ..RansomwareConfig::default() };
        let mut d = Detector::new(&cfg);
        // container_format_burst_file_count = 15 * 3 = 45
        let mut verdict = Verdict::Clean;
        for i in 0..45 {
            verdict = d.observe_container_format_write(
                1234,
                Path::new(&format!("/home/test/new_dir_no_baseline/file_{i}.zip")),
            );
        }
        assert!(
            matches!(verdict, Verdict::Burst { .. }),
            "global container-format counter must fire even in a directory with no baseline"
        );
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