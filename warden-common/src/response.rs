use std::path::PathBuf;

use tracing::{info, warn};

use crate::event::{DetectionEvent, Mode, Severity};
use crate::process;
use crate::quarantine::Quarantine;

/// Shared, synchronous response path for any detection module that needs to
/// neutralize a suspect process right now: SIGSTOP, quarantine every file it
/// touched, SIGKILL, then build the `DetectionEvent` describing what
/// happened for the dispatcher to log/notify. Kept synchronous (no channel
/// round-trip) so response latency is bounded only by this function's own
/// work, not by how busy the dispatcher's queue is - the one thing that
/// must never be slow when a ransomware burst is actively encrypting files.
///
/// In `Monitor` mode nothing is touched: the event is still built and
/// reported so the user can see what would have happened before switching
/// to `Enforce`.
pub fn handle_detection(
    mode: Mode,
    module: &'static str,
    severity: Severity,
    pid: i32,
    reason: &str,
    affected_paths: Vec<PathBuf>,
    quarantine: &Quarantine,
) -> DetectionEvent {
    warn!(module, pid, reason, ?affected_paths, "suspicious behavior detected");

    if mode == Mode::Monitor {
        return DetectionEvent::new(module, severity, reason, "monitor mode: process and files left untouched")
            .with_response(pid, affected_paths, false);
    }

    if let Err(e) = process::stop_then_kill(pid) {
        warn!(module, pid, error = %e, "failed to stop/kill suspect process (may have already exited)");
    }

    let mut quarantined = Vec::new();
    for path in &affected_paths {
        match quarantine.take(path, module, pid, reason) {
            Ok(Some(dest)) => quarantined.push(dest),
            Ok(None) => info!(path = %path.display(), "file already gone, nothing to quarantine"),
            Err(e) => warn!(path = %path.display(), error = %e, "failed to quarantine file"),
        }
    }

    let detail = format!("process killed, {} file(s) quarantined", quarantined.len());
    DetectionEvent::new(module, severity, reason, detail).with_response(pid, quarantined, true)
}
