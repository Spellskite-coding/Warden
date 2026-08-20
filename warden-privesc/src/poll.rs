use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};
use warden_common::event::{DetectionEvent, Mode, Severity};
use warden_common::permissions::strip_setuid_setgid;
use warden_common::quarantine::Quarantine;
use warden_common::response;

use crate::baseline;
use crate::config::PrivescConfig;

const MODULE: &str = "privesc";
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A binary under one of the standard `$PATH` directories unexpectedly
/// gaining setuid/setgid. The safe Enforce response is to strip the bit
/// back off, not delete the file: it may otherwise be an entirely
/// legitimate system binary (`chmod +s /usr/bin/find` is a well-known
/// GTFOBins privesc technique that doesn't stop `find` from also being
/// the real `find` the system needs elsewhere).
fn handle_system_binary(mode: Mode, path: &Path) -> DetectionEvent {
    let reason = format!("system binary gained setuid/setgid: {}", path.display());
    warn!(module = MODULE, path = %path.display(), "suspicious behavior detected");

    if mode == Mode::Monitor {
        return DetectionEvent::new(MODULE, Severity::Critical, &reason, "monitor mode: permissions left untouched")
            .with_response(None, vec![path.to_path_buf()], false);
    }

    match strip_setuid_setgid(path) {
        Ok(true) => {
            info!(path = %path.display(), "stripped setuid/setgid bit");
            DetectionEvent::new(MODULE, Severity::Critical, &reason, "setuid/setgid bit stripped").with_response(
                None,
                vec![path.to_path_buf()],
                true,
            )
        }
        Ok(false) => DetectionEvent::new(MODULE, Severity::Critical, &reason, "file already gone or already clean by the time we acted")
            .with_response(None, vec![], false),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to strip setuid/setgid bit");
            DetectionEvent::new(MODULE, Severity::Critical, &reason, format!("failed to strip setuid/setgid bit: {e}"))
                .with_response(None, vec![], false)
        }
    }
}

/// A brand-new setuid/setgid file in world-writable scratch space or the
/// target user's own files - nothing legitimate needs one there, so it's
/// safe to quarantine outright.
fn handle_new_file(mode: Mode, path: &Path, quarantine: &Quarantine) -> DetectionEvent {
    let summary = format!("new setuid/setgid file appeared: {}", path.display());
    response::handle_file_only_detection(
        mode,
        MODULE,
        Severity::Critical,
        &summary,
        "detected via periodic scan, no originating process available",
        path,
        quarantine,
    )
}

/// Periodic poll loop, checked every `POLL_INTERVAL`. Not fanotify-based
/// like the other filesystem-watching modules: `FAN_ATTRIB` was tried
/// first and found, by testing, to fail with `EINVAL` regardless of mark
/// scope - the kernel requires the fanotify group to be initialized with
/// `FAN_REPORT_FID` for this event, a flag the `nix` crate's fanotify
/// bindings don't expose. Real-time attrib-change notification would need
/// hand-rolled raw fanotify syscalls (and FID-based event parsing `nix`
/// doesn't support either) or an eBPF hook on the chmod family of
/// syscalls - both bigger undertakings than a privilege-escalation
/// surface that isn't as time-critical as active ransomware or a live
/// exec/connection warrants for a first version. Polling is simple,
/// correct, and easy to reason about; a few seconds of detection latency
/// is an acceptable trade-off here, unlike everywhere else in Warden.
pub fn run(
    cfg: PrivescConfig,
    home: &Path,
    mode: Mode,
    event_tx: tokio::sync::mpsc::UnboundedSender<DetectionEvent>,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let watch_dirs = cfg.resolve_watch_dirs(home);
    if watch_dirs.is_empty() {
        let e = anyhow::anyhow!("no watch directories resolved");
        let _ = ready_tx.send(Err(e.to_string()));
        return Err(e);
    }

    let quarantine = match Quarantine::new(Path::new("/var/lib/warden/quarantine")).context("initializing quarantine") {
        Ok(q) => q,
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let all_dirs = watch_dirs.all();
    // Immutable ground truth: whatever already carried setuid/setgid
    // before Warden started watching is presumed legitimate forever, so a
    // routine package upgrade re-touching /usr/bin/sudo never gets
    // flagged.
    let baseline = baseline::seed(&all_dirs);
    // The working set of currently-unresolved anomalies already reported
    // this run, so an anomaly that's still sitting there five seconds
    // later isn't re-reported every tick. Cleared for a path once it's no
    // longer observed with the bit set, so a genuine re-infection after
    // remediation is treated as a fresh incident.
    let mut already_flagged: HashSet<PathBuf> = HashSet::new();

    let _ = ready_tx.send(Ok(()));
    info!(?mode, system_bin_dirs = watch_dirs.system_bin_dirs.len(), quarantine_dirs = watch_dirs.quarantine_dirs.len(), baseline_suid_sgid = baseline.len(), "privesc poll loop started");

    loop {
        std::thread::sleep(POLL_INTERVAL);
        let current = baseline::rescan(&all_dirs);

        for path in &current {
            if baseline.contains(path) || already_flagged.contains(path) {
                continue;
            }

            let evt =
                if watch_dirs.is_system_bin_dir(path) { handle_system_binary(mode, path) } else { handle_new_file(mode, path, &quarantine) };

            if !evt.action_taken {
                already_flagged.insert(path.clone());
            }
            let _ = event_tx.send(evt);
        }

        already_flagged.retain(|p| current.contains(p));
    }
}
