use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-PID cache in front of the shared `warden_common::exceptions` store
/// (path + SHA-256 exemptions, managed via `warden --add-exception` and
/// the GUI): a burst of many high-entropy writes from the same process
/// within the detection window would otherwise re-hash its executable on
/// every single write, which matters for large binaries.
///
/// Keyed on PID alone, so every cache hit also carries the target
/// process's kernel start time and revalidates it on every hit, not just
/// on TTL expiry - a bare `(bool, Instant)` cache was a real bypass: the
/// kernel reuses PIDs, `install.sh` hash-exempts Warden's own binaries by
/// path, `warden --set_mode` restarts every module's process, and any
/// admin-exempted tool exiting is enough - a short-lived ransomware
/// process spawned soon after and unlucky enough to inherit the same PID
/// within `cache_ttl` would otherwise silently inherit its "trusted"
/// verdict and skip the burst detector entirely (`observe_high_entropy_write`
/// is never even called for a trusted PID - see `fanotify_monitor.rs`).
pub struct TrustStore {
    cache: HashMap<i32, (bool, Instant, u64)>,
    cache_ttl: Duration,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore {
    pub fn new() -> Self {
        Self { cache: HashMap::new(), cache_ttl: Duration::from_secs(60) }
    }

    pub fn is_trusted(&mut self, pid: i32) -> bool {
        let now = Instant::now();
        let current_start = process_start_time(pid);

        if let Some((trusted, checked_at, cached_start)) = self.cache.get(&pid) {
            if now.duration_since(*checked_at) < self.cache_ttl && current_start == Some(*cached_start) {
                return *trusted;
            }
        }

        let result = warden_common::exceptions::is_exempt_pid(pid);
        self.cache.insert(pid, (result, now, current_start.unwrap_or(0)));
        self.cache.retain(|_, (_, checked_at, _)| now.duration_since(*checked_at) < self.cache_ttl * 4);
        result
    }
}

/// A process's start time: field 22 of `/proc/<pid>/stat`, in clock
/// ticks since boot - immutable for the entire lifetime of a given PID,
/// and the standard, no-extra-privilege way to tell "still the same
/// process" apart from "a different process that got the same,
/// kernel-recycled PID number". Parsed from the last `)` onward rather
/// than by naive whitespace-splitting from the start of the line: the
/// second field (the command name) is a kernel-truncated string
/// enclosed in parens that can itself legitimately contain spaces or
/// parens.
fn process_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_start_time_is_readable_and_stable() {
        let pid = std::process::id() as i32;
        let a = process_start_time(pid).expect("should read our own start time");
        let b = process_start_time(pid).expect("should read our own start time again");
        assert_eq!(a, b, "a still-alive process's start time must not change between reads");
    }

    #[test]
    fn nonexistent_pid_returns_none() {
        // PID 1 always exists (init/systemd); an implausibly large PID
        // almost certainly does not, without depending on any specific
        // process actually being absent at test time.
        assert_eq!(process_start_time(i32::MAX), None);
    }

    #[test]
    fn cache_hit_is_rejected_when_the_pid_was_recycled_by_a_different_process() {
        let mut store = TrustStore::new();
        let pid = 424242;

        // Simulate a first, trusted sighting of `pid` (as if
        // `is_exempt_pid` had returned true for whatever process held it
        // at the time), stamped with a start time that does NOT match
        // any real process.
        store.cache.insert(pid, (true, Instant::now(), 999_999_999));

        // A real call to `is_trusted` for this PID re-reads its CURRENT
        // start time (this process's real one, since 424242 is unlikely
        // to be a live PID in the test environment, `process_start_time`
        // returns `None` here) - which can never equal the stale cached
        // `999_999_999`, so the stale "trusted" verdict must not be
        // reused even though the TTL alone would still allow it.
        let trusted = store.is_trusted(pid);
        assert!(!trusted, "a cache entry for a recycled PID must be revalidated, not blindly trusted off TTL alone");
    }
}
