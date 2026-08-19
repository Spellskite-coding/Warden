use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use nix::unistd::Whence;
use tracing::{debug, info, warn};
use warden_common::event::{Mode, Severity};
use warden_common::quarantine::Quarantine;
use warden_common::response;

use crate::baseline;
use crate::config::RansomwareConfig;
use crate::detector::{Detector, Verdict};
use crate::entropy::shannon_entropy;
use crate::honeypot;
use crate::trust::TrustStore;

const MODULE: &str = "ransomware";

const WATCHED_EVENTS: MaskFlags =
    MaskFlags::from_bits_truncate(MaskFlags::FAN_CLOSE_WRITE.bits() | MaskFlags::FAN_MODIFY.bits());

/// One-time setup: initialize the fanotify group, mark the filesystem(s)
/// backing the watched directories, and seed the plaintext-directory
/// baseline.
///
/// Unlike a server where the watched data lives on its own dedicated mount,
/// a workstation's `$HOME` almost always sits on the same root filesystem
/// as the rest of the OS. `FAN_MARK_FILESYSTEM` marks the *entire*
/// filesystem a given path belongs to, so marking e.g. `~/Documents` this
/// way on a single-partition system means the kernel will report events for
/// all of `/` - not just the user's data. Rather than lose the ability to
/// watch recursively (the only alternative, per-directory marks, cannot
/// see into newly created subdirectories without separately tracking every
/// `mkdir`), we accept the wider kernel-side scope and filter in
/// `is_under_watch_dirs` before doing any expensive work (reading the file,
/// computing entropy) on an event outside the directories we actually
/// care about.
fn init(cfg: &RansomwareConfig) -> Result<(Fanotify, Detector, Arc<Quarantine>)> {
    let group = Fanotify::init(
        InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC | InitFlags::FAN_UNLIMITED_QUEUE,
        EventFFlags::O_RDONLY,
    )
    .context("fanotify_init failed (need CAP_SYS_ADMIN, i.e. run as root)")?;

    let mut marked_devices: HashSet<u64> = HashSet::new();
    for dir in &cfg.watch_dirs {
        let handle = std::fs::File::open(dir).with_context(|| format!("opening watch dir {}", dir.display()))?;
        let dev = handle.metadata().map(|m| m.dev()).unwrap_or(0);
        if !marked_devices.insert(dev) {
            debug!(dir = %dir.display(), "filesystem already marked via another watch dir, skipping duplicate mark");
            continue;
        }

        group
            .mark(MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM, WATCHED_EVENTS, &handle, None::<&Path>)
            .with_context(|| format!("fanotify_mark failed for {}", dir.display()))?;
        info!(dir = %dir.display(), "watching (filesystem-wide mark, filtered to configured directories)");
    }

    let mut detector = Detector::new(cfg);
    let quarantine = Arc::new(Quarantine::new(Path::new("/var/lib/warden/quarantine"))?);

    for dir in &cfg.watch_dirs {
        baseline::seed(&mut detector, dir, cfg.sample_bytes, cfg.entropy_threshold);
    }

    Ok((group, detector, quarantine))
}

fn is_under_watch_dirs(path: &Path, watch_dirs: &[PathBuf]) -> bool {
    watch_dirs.iter().any(|w| path.starts_with(w))
}

/// Blocking fanotify read/dispatch loop. Meant to run on a dedicated
/// (blocking) thread: `Fanotify::read_events` blocks the calling thread
/// until events are available.
///
/// `ready_tx` is signaled exactly once, right after initialization
/// succeeds or fails, so the caller can gate systemd `READY=1` (and thus
/// `Restart=on-failure` semantics) on monitoring having actually come up.
pub fn run(
    cfg: RansomwareConfig,
    home: &Path,
    mode: Mode,
    event_tx: tokio::sync::mpsc::UnboundedSender<warden_common::event::DetectionEvent>,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let cfg = cfg.resolve_defaults(home);
    if cfg.watch_dirs.is_empty() {
        let e = anyhow::anyhow!("no watch directories resolved (none of the default $HOME subdirectories exist, and none were configured)");
        let _ = ready_tx.send(Err(e.to_string()));
        return Err(e);
    }

    let sample_bytes = cfg.sample_bytes;
    let watch_dirs = cfg.watch_dirs.clone();

    let honeypots = match honeypot::provision(&cfg.honeypots) {
        Ok(h) => h,
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let (group, mut detector, quarantine) = match init(&cfg) {
        Ok(v) => {
            let _ = ready_tx.send(Ok(()));
            v
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let own_pid = std::process::id() as i32;
    let mut trust = TrustStore::new(cfg.trusted_executables.clone());
    info!(?mode, watch_dirs = ?watch_dirs, trusted_executables = cfg.trusted_executables.len(), "ransomware monitor loop started");

    const MAX_CONSECUTIVE_READ_FAILURES: u32 = 20;
    let mut consecutive_failures = 0u32;

    loop {
        let events = match group.read_events() {
            Ok(ev) => {
                consecutive_failures = 0;
                ev
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_READ_FAILURES {
                    return Err(e).context(format!("fanotify read_events failed {consecutive_failures} times in a row, giving up"));
                }
                warn!(error = %e, consecutive_failures, "fanotify read_events failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(200 * consecutive_failures.min(10) as u64));
                continue;
            }
        };

        for event in events {
            let pid = event.pid();
            if pid == own_pid || pid <= 0 {
                continue;
            }

            let Some(fd) = event.fd() else {
                warn!("fanotify event queue overflowed; some events were dropped");
                continue;
            };

            let path = std::fs::read_link(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd)))
                .unwrap_or_else(|_| PathBuf::from("<unknown>"));

            if !is_under_watch_dirs(&path, &watch_dirs) {
                continue;
            }

            if honeypot::is_honeypot(&honeypots, &path) {
                let mut affected = detector.files_for_pid(pid);
                affected.push(path.clone());
                let evt = response::handle_detection(
                    mode,
                    MODULE,
                    Severity::Critical,
                    pid,
                    &format!("honeypot touched: {}", path.display()),
                    affected,
                    &quarantine,
                );
                let _ = event_tx.send(evt);
                detector.forget(pid);
                continue;
            }

            let mut buf = vec![0u8; sample_bytes];
            let _ = nix::unistd::lseek(fd, 0, Whence::SeekSet);
            let n = nix::unistd::read(fd, &mut buf).unwrap_or(0);
            buf.truncate(n);

            if buf.is_empty() {
                continue;
            }

            let entropy = shannon_entropy(&buf);
            debug!(pid, path = %path.display(), entropy, "file write observed");

            if entropy < cfg.entropy_threshold {
                detector.note_plaintext_activity(&path);
            } else if trust.is_trusted(pid) {
                debug!(pid, path = %path.display(), "high-entropy write from a trusted executable, not counting toward burst");
            } else if let Verdict::Burst { count } = detector.observe_high_entropy_write(pid, &path) {
                let affected = detector.files_for_pid(pid);
                let evt = response::handle_detection(
                    mode,
                    MODULE,
                    Severity::Critical,
                    pid,
                    &format!("{count} high-entropy file rewrites within {}s (last: {})", cfg.burst_window_secs, path.display()),
                    affected,
                    &quarantine,
                );
                let _ = event_tx.send(evt);
                detector.forget(pid);
            }
        }
    }
}
