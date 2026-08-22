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
// Was 5s; a security review pointed out the classic GTFOBins pattern
// (`cp bash x; chmod +s x; x -p; chmod -s x`) is a one-line script that
// completes in well under a second, so the old interval wasn't "a few
// seconds of latency" for a scripted attacker - it was closer to a
// 100%-reliable bypass, since the setuid bit was never observed at any
// poll tick. 2s meaningfully shrinks that window (verified live: even at
// 5s the recursive rescan already hits its own file cap every cycle on a
// real box, so this isn't free - shrinking further risks the scan not
// finishing before the next tick). Still doesn't catch a sub-second
// scripted round-trip; closing that fully needs the event-driven
// FAN_ATTRIB/eBPF approach described below, not a smaller number here.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A binary under one of the standard `$PATH` directories unexpectedly
/// gaining setuid/setgid. The safe Enforce response is to strip the bit
/// back off, not delete the file: it may otherwise be an entirely
/// legitimate system binary (`chmod +s /usr/bin/find` is a well-known
/// GTFOBins privesc technique that doesn't stop `find` from also being
/// the real `find` the system needs elsewhere).
/// Returns the event to report, plus whether this path should be
/// remembered in `already_flagged` (never re-evaluated again until it
/// disappears from a scan). A review found the original version marked
/// EVERY non-acting outcome sticky, including "a package manager is
/// active right now" - a transient condition, not a permanent one. Since
/// nothing ever clears an entry from `already_flagged` except the path
/// vanishing from `current` (see `run`'s loop), a setuid backdoor dropped
/// during the brief, routine window a real package manager happens to be
/// running got suppressed once and then silently NEVER reconsidered
/// again, even seconds later once the update finished - a permanent,
/// Enforce-mode bypass for a GTFOBins-style attack timed to piggyback on
/// legitimate update activity. Only a real exception is genuinely
/// permanent; every other non-acting outcome here must be retried on the
/// next tick.
fn handle_system_binary(mode: Mode, path: &Path) -> (DetectionEvent, bool) {
    let reason = format!("system binary gained setuid/setgid: {}", path.display());
    warn!(module = MODULE, path = %path.display(), "suspicious behavior detected");

    if mode == Mode::Monitor {
        return (
            DetectionEvent::new(MODULE, Severity::Critical, &reason, "monitor mode: permissions left untouched").with_response(None, vec![path.to_path_buf()], false),
            false,
        );
    }

    if warden_common::exceptions::is_exempt(path) {
        return (
            DetectionEvent::new(MODULE, Severity::Critical, &reason, "exempted: permissions left untouched").with_response(None, vec![path.to_path_buf()], false),
            true,
        );
    }

    // A freshly-installed/upgraded package can legitimately ship a new
    // setuid/setgid binary (e.g. a packet-capture or privilege-helper
    // tool) - suppress the strip while a trusted installer is active
    // rather than breaking it the moment it's installed. Deliberately
    // NOT sticky (see this function's doc comment): re-evaluated fresh
    // every tick, so the strip actually happens the moment the real
    // package manager exits, instead of never.
    if warden_common::package_manager::is_active() {
        return (
            DetectionEvent::new(MODULE, Severity::Critical, &reason, "package manager active: permissions left untouched, review recommended")
                .with_response(None, vec![path.to_path_buf()], false),
            false,
        );
    }

    match strip_setuid_setgid(path) {
        Ok(true) => {
            info!(path = %path.display(), "stripped setuid/setgid bit");
            (
                DetectionEvent::new(MODULE, Severity::Critical, &reason, "setuid/setgid bit stripped").with_response(None, vec![path.to_path_buf()], true),
                false,
            )
        }
        Ok(false) => (
            DetectionEvent::new(MODULE, Severity::Critical, &reason, "file already gone or already clean by the time we acted").with_response(None, vec![], false),
            false,
        ),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to strip setuid/setgid bit");
            (
                DetectionEvent::new(MODULE, Severity::Critical, &reason, format!("failed to strip setuid/setgid bit: {e}")).with_response(None, vec![], false),
                false,
            )
        }
    }
}

/// A brand-new setuid/setgid file in world-writable scratch space or the
/// target user's own files - nothing legitimate needs one there, so it's
/// safe to quarantine outright.
///
/// Except while a package manager is active: `update-initramfs`/
/// `mkinitramfs` (triggered by any kernel package upgrade) legitimately
/// stages copies of setuid system binaries like `ntfs-3g` under
/// `/var/tmp/mkinitramfs_XXXXXX/` while building the boot initrd - the
/// exact same shape of trusted-installer activity `handle_system_binary`
/// already accounts for, just via a different code path since this one
/// is scratch-dir quarantine, not a system-bin-dir strip.
/// Same `(event, sticky)` reasoning as `handle_system_binary` - see its
/// doc comment. The package-manager-active branch here has the identical
/// bug for the same reason (`update-initramfs` staging a setuid copy
/// under `/var/tmp` during a real kernel upgrade): not sticky, so a
/// setuid drop in scratch space that piggybacks on that window is still
/// quarantined the moment the legitimate installer activity ends.
fn handle_new_file(mode: Mode, path: &Path, quarantine: &Quarantine) -> (DetectionEvent, bool) {
    let summary = format!("new setuid/setgid file appeared: {}", path.display());

    if mode == Mode::Enforce && warden_common::exceptions::is_exempt(path) {
        return (
            DetectionEvent::new(MODULE, Severity::Critical, &summary, "exempted: file left untouched").with_response(None, vec![path.to_path_buf()], false),
            true,
        );
    }

    if mode == Mode::Enforce && warden_common::package_manager::is_active() {
        warn!(module = MODULE, path = %path.display(), "suspicious behavior detected");
        return (
            DetectionEvent::new(MODULE, Severity::Critical, &summary, "package manager active: file left untouched, review recommended")
                .with_response(None, vec![path.to_path_buf()], false),
            false,
        );
    }

    (
        response::handle_file_only_detection(
            mode,
            MODULE,
            Severity::Critical,
            &summary,
            "detected via periodic scan, no originating process available",
            path,
            quarantine,
        ),
        false,
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

            let (evt, sticky) =
                if watch_dirs.is_system_bin_dir(path) { handle_system_binary(mode, path) } else { handle_new_file(mode, path, &quarantine) };

            if sticky {
                already_flagged.insert(path.clone());
            }
            let _ = event_tx.send(evt);
        }

        already_flagged.retain(|p| current.contains(p));
    }
}
