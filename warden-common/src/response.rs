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
            .with_response(Some(pid), affected_paths, false);
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
    DetectionEvent::new(module, severity, reason, detail).with_response(Some(pid), quarantined, true)
}

/// Response path for modules with no associated process to act on (e.g.
/// persistence: inotify never reports who wrote a file, unlike fanotify).
/// Quarantines a single standalone file - never call this for something a
/// legitimate process might still have open or depend on existing, since
/// there's no PID to stop first. `pid` in the resulting event is always
/// `None`, not a sentinel like `0`: passing `0` to a kill-capable path
/// elsewhere would signal an entire process group, so this function
/// deliberately never touches `process::stop_then_kill` at all.
pub fn handle_file_only_detection(
    mode: Mode,
    module: &'static str,
    severity: Severity,
    summary: &str,
    detail: &str,
    file: &std::path::Path,
    quarantine: &Quarantine,
) -> DetectionEvent {
    warn!(module, summary, detail, path = %file.display(), "suspicious file change detected");

    if mode == Mode::Monitor {
        return DetectionEvent::new(module, severity, summary, format!("{detail} (monitor mode: file left untouched)"))
            .with_response(None, vec![file.to_path_buf()], false);
    }

    match quarantine.take(file, module, -1, summary) {
        Ok(Some(dest)) => {
            let full_detail = format!("{detail} (quarantined to {})", dest.display());
            DetectionEvent::new(module, severity, summary, full_detail).with_response(None, vec![dest], true)
        }
        Ok(None) => DetectionEvent::new(module, severity, summary, format!("{detail} (file already gone, nothing to quarantine)"))
            .with_response(None, vec![], false),
        Err(e) => {
            warn!(module, path = %file.display(), error = %e, "failed to quarantine file");
            DetectionEvent::new(module, severity, summary, format!("{detail} (failed to quarantine: {e})")).with_response(None, vec![], false)
        }
    }
}
