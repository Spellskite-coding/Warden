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
/// - **Globally, PID- and directory-agnostic** - two variants:
///   `recent_writes_global` for directories that already have a plaintext
///   baseline, and `recent_writes_global_unbaselined` for ones that don't.
///   A red-team-confirmed bypass of the first two counters - fork-per-file
///   *combined with* spreading those files across several watched
///   directories at once (e.g. `burst_file_count - 1` files each in every
///   one of the default six watch dirs) keeps every single per-PID AND
///   per-directory count individually under threshold while still
///   touching dozens of distinct files within the window. Reproduced live
///   end-to-end: 48 files across 6 directories, 8 per directory, one
///   short-lived process per file - zero detections, zero quarantines.
///   The per-directory counter alone only bounds a *single* directory's
///   count, never the sum across all of them; this global counter closes
///   that gap the same way `recent_writes_by_dir` closes the per-PID one.
///
///   A second, independently red-team-confirmed bypass (external report,
///   full writeup and PoC in PROGRESS.md) targeted the *unbaselined* case
///   specifically: `has_baseline()` used to gate ALL THREE counters,
///   including this global one, so a directory that had simply never
///   received a plaintext write before (any freshly-created subdirectory,
///   any Pictures/Videos folder that only ever holds container-format
///   files and so never triggers `note_plaintext_activity`) was
///   completely invisible to burst detection no matter how many files
///   got encrypted in it. `recent_writes_global_unbaselined` exists so
///   that gap closes at the SAME threshold as the baselined path, not a
///   looser one - a separate map (rather than reusing
///   `recent_writes_global` under a different threshold depending on
///   which write happens to land last) avoids the verdict becoming
///   order-dependent and keeps `files_for_pid` attribution consistent.
///   Deliberately not given a higher/looser threshold than the baselined
///   global counter: doing so would hand ransomware a mechanical
///   incentive to prefer fresh directories specifically because they
///   carry a bigger allowance, which defeats the entire point of closing
///   this bypass in the first place.
///
/// - **Per originating PID, unconditionally** (still `recent_writes_by_pid`,
///   at the same threshold as everywhere else): also no longer gated on
///   `has_baseline()`, for the same reason as the global counters just
///   above - a single non-forking process encrypting many files in a
///   fresh directory needs to be caught by *something* even before the
///   global counter's aggregate threshold is reached, exactly as it
///   already is in a baselined directory. Per-directory tracking alone
///   stays gated on baseline (see below) since it's the counter most
///   prone to false-positiving on a directory that legitimately only
///   ever receives bulk container-format content; per-PID and global
///   don't share that risk the same way and so don't need the same gate.
///
/// Also tracks, per directory, whether ordinary (low-entropy) content has
/// ever been seen there. A burst of high-entropy writes in a directory
/// with a baseline gets an extra, more sensitive check (the per-directory
/// counter, gated on this) on top of the two unconditional ones above -
/// otherwise a directory that only ever receives already-compressed
/// output would trip that particular counter on ordinary bulk activity.
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
        let threshold = self.burst_file_count;
        let has_baseline = self.has_baseline(path);

        // Per-PID and (one of) the global counters run unconditionally -
        // see the struct doc comment for why gating them on `has_baseline`
        // was the actual bug being fixed here.
        if let Some(affected) = Self::record_and_check(&mut self.recent_writes_by_pid, pid, path, now, window, threshold) {
            return Verdict::Burst { affected };
        }

        if has_baseline {
            if let Some(affected) = Self::record_and_check(&mut self.recent_writes_global, (), path, now, window, threshold) {
                return Verdict::Burst { affected };
            }
            if let Some(dir) = path.parent() {
                if let Some(affected) = Self::record_and_check(&mut self.recent_writes_by_dir, dir.to_path_buf(), path, now, window, threshold) {
                    return Verdict::Burst { affected };
                }
            }
        } else if let Some(affected) = Self::record_and_check(&mut self.recent_writes_global_unbaselined, (), path, now, window, threshold) {
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

        if let Some(affected) = Self::record_and_check(&mut self.recent_container_format_writes_by_pid, pid, path, now, window, threshold) {
            return Verdict::Burst { affected };
        }

        if has_baseline {
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
        } else if let Some(affected) = Self::record_and_check(&mut self.recent_container_format_writes_global_unbaselined, (), path, now, window, threshold) {
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

    /// Drops every per-PID/per-directory outer entry whose tracked writes
    /// have all aged out of the burst window.
    ///
    /// `record_and_check` prunes a key's *inner* map (the timestamped
    /// paths) on every write to that same key, but it never removes the
    /// *outer* key itself even once that inner map is left empty - and
    /// for a PID that writes exactly once and then exits (the overwhelming
    /// common case: PIDs churn constantly, most never come back), nothing
    /// ever touches that key again to trigger a prune. `recent_writes_by_pid`
    /// and `recent_writes_by_dir` (and their container-format counterparts)
    /// therefore grow by roughly one entry per distinct PID/directory ever
    /// observed, for as long as the daemon runs - a real unbounded-memory
    /// finding on a long-lived workstation daemon, found by review rather
    /// than live reproduction (the growth is slow enough that it wouldn't
    /// show up in a normal test run). The two global maps aren't included
    /// here: keyed on a single unit `()`, they're re-pruned on every
    /// single write regardless of which PID/directory it came from, so
    /// they don't share this growth pattern.
    ///
    /// Meant to be called periodically (not on every event - see the
    /// caller in `fanotify_monitor::run`) rather than after every write,
    /// since a full sweep costs O(total tracked PIDs + directories).
    pub fn prune_expired(&mut self, now: Instant) {
        let window = self.burst_window;
        for map in [&mut self.recent_writes_by_pid, &mut self.recent_container_format_writes_by_pid] {
            map.retain(|_, files| {
                files.retain(|_, &mut seen| now.duration_since(seen) <= window);
                !files.is_empty()
            });
        }
        for map in [&mut self.recent_writes_by_dir, &mut self.recent_container_format_writes_by_dir] {
            map.retain(|_, files| {
                files.retain(|_, &mut seen| now.duration_since(seen) <= window);
                !files.is_empty()
            });
        }
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

    fn detector_with_baseline_required(burst_file_count: usize) -> Detector {
        let cfg = RansomwareConfig { burst_file_count, require_directory_baseline: true, ..RansomwareConfig::default() };
        Detector::new(&cfg)
    }

    /// Regression test for the externally-reported "no-baseline bypass":
    /// a directory that never received a plaintext write (any freshly
    /// created subdirectory) used to be completely invisible to ALL
    /// THREE counters, including the global one. 20 files from 20
    /// distinct short-lived PIDs (the exact shape of the reported PoC)
    /// in a directory with no baseline must still trigger, at the same
    /// threshold a baselined directory would.
    #[test]
    fn burst_in_a_directory_with_no_baseline_is_still_caught_by_the_global_counter() {
        let mut d = detector_with_baseline_required(15);
        let mut verdict = Verdict::Clean;
        for i in 0..20 {
            verdict = d.observe_high_entropy_write(50_000 + i, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "20 files across 20 distinct pids in a never-baselined directory must trigger");
    }

    /// Same PoC shape, container-format path.
    #[test]
    fn container_format_burst_in_a_directory_with_no_baseline_is_still_caught() {
        let mut d = detector_with_baseline_required(15); // container_format_burst_file_count = 45
        let mut verdict = Verdict::Clean;
        for i in 0..45 {
            verdict = d.observe_container_format_write(60_000 + i, Path::new(&format!("/home/test/new_dir/file_{i}.zip")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "45 container-format writes across distinct pids in a never-baselined directory must trigger");
    }

    /// A single non-forking process writing into a fresh, never-baselined
    /// directory must be caught by the now-unconditional per-PID counter,
    /// without needing to wait for the (also unconditional, but
    /// process-agnostic) global-unbaselined counter to separately reach
    /// threshold.
    #[test]
    fn single_pid_burst_in_a_directory_with_no_baseline_is_caught_by_per_pid() {
        let mut d = detector_with_baseline_required(15);
        let mut verdict = Verdict::Clean;
        for i in 0..15 {
            verdict = d.observe_high_entropy_write(1234, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "15 files from one pid in a never-baselined directory must trigger");
    }

    /// The unbaselined global counter must use the SAME threshold as the
    /// baselined one - not a looser one. A looser threshold would hand
    /// ransomware a mechanical incentive to prefer fresh directories,
    /// re-opening (at a higher file count) the exact bypass this is
    /// meant to close.
    #[test]
    fn unbaselined_global_threshold_matches_the_baselined_one() {
        let mut d = detector_with_baseline_required(15);
        d.note_plaintext_activity(Path::new("/home/test/docs/readme.txt"));
        // 14 baselined writes from distinct pids, one dir - under both
        // per-pid and per-dir thresholds, exercises the global-baselined
        // path specifically.
        for i in 0..14 {
            d.observe_high_entropy_write(1000 + i, Path::new(&format!("/home/test/docs/file_{i}.enc")));
        }
        // 14 unbaselined writes from distinct pids, a different dir.
        let mut verdict = Verdict::Clean;
        for i in 0..14 {
            verdict = d.observe_high_entropy_write(2000 + i, Path::new(&format!("/home/test/new_dir/file_{i}.enc")));
        }
        assert_eq!(verdict, Verdict::Clean, "14 is still one below the 15 threshold on either path");

        verdict = d.observe_high_entropy_write(2100, Path::new("/home/test/new_dir/file_last.enc"));
        assert!(matches!(verdict, Verdict::Burst { .. }), "the 15th unbaselined write must trigger at the same threshold as the baselined path");
    }

    /// Directories that legitimately only ever hold container-format
    /// content (a Pictures/Videos folder) never call `note_plaintext_activity`,
    /// so `has_baseline` never becomes true for them - the per-directory
    /// counter (gated on baseline, to avoid false-positiving on bulk
    /// legitimate imports) stays silent, but the unconditional per-PID and
    /// global-unbaselined counters must still catch a real burst there.
    #[test]
    fn a_pictures_style_directory_that_never_gets_a_baseline_is_still_protected() {
        let mut d = detector_with_baseline_required(15);
        let mut verdict = Verdict::Clean;
        for i in 0..20 {
            verdict = d.observe_high_entropy_write(70_000 + i, Path::new(&format!("/home/test/Pictures/photo_{i}.raw")));
        }
        assert!(matches!(verdict, Verdict::Burst { .. }), "a directory that only ever holds container-format content must still be covered by the global counter");
    }

    /// Regression test for the memory-leak finding: a PID that writes
    /// once, well under threshold, and never writes again must not leave
    /// a permanent entry in the per-PID map once its write has aged out
    /// of the burst window.
    #[test]
    fn prune_expired_removes_stale_per_pid_and_per_dir_entries() {
        let mut d = detector_with_threshold(15);
        let start = Instant::now();
        for pid in 0..500 {
            d.observe_high_entropy_write(pid, Path::new(&format!("/home/test/Documents/once_{pid}.bin")));
        }
        assert_eq!(d.recent_writes_by_pid.len(), 500, "sanity check: every one-off pid left an entry");

        let long_after_window = start + d.burst_window + Duration::from_secs(1);
        d.prune_expired(long_after_window);

        assert!(d.recent_writes_by_pid.is_empty(), "every entry should have aged out of the burst window and been pruned");
        assert!(d.recent_writes_by_dir.values().all(|m| !m.is_empty()) || d.recent_writes_by_dir.is_empty(), "no stale empty inner maps left behind");
    }
}
