use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use tracing::{debug, info, warn};
use warden_common::event::{Mode, Severity};
use warden_common::quarantine::Quarantine;
use warden_common::response;

use crate::config::YaraConfig;
use crate::rules;

const MODULE: &str = "yara";

const WATCHED_EVENTS: MaskFlags = MaskFlags::FAN_CLOSE_WRITE;

fn is_under_watch_dirs(path: &Path, watch_dirs: &[PathBuf]) -> bool {
    watch_dirs.iter().any(|w| path.starts_with(w))
}

/// One-time setup: initialize the fanotify group, mark the filesystem(s)
/// backing the watched directories, and compile the YARA rule set. Same
/// filesystem-wide-mark-then-userspace-filter approach as the ransomware
/// module, for the same reason - see
/// `warden_ransomware::fanotify_monitor::init`.
fn init(watch_dirs: &[PathBuf], custom_rules_dir: &Path) -> Result<(Fanotify, yara_x::Rules, Quarantine)> {
    let group = Fanotify::init(
        InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC | InitFlags::FAN_UNLIMITED_QUEUE,
        EventFFlags::O_RDONLY,
    )
    .context("fanotify_init failed (need CAP_SYS_ADMIN, i.e. run as root)")?;

    let mut marked_devices: HashSet<u64> = HashSet::new();
    for dir in watch_dirs {
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

    let quarantine = Quarantine::new(Path::new("/var/lib/warden/quarantine"))?;
    Ok((group, rules::compile(Some(custom_rules_dir))?, quarantine))
}

/// Blocking fanotify read/dispatch loop - see
/// `warden_ransomware::fanotify_monitor::run` for the equivalent
/// readiness-gating and retry-backoff pattern this mirrors. Meant to run
/// on a dedicated blocking thread.
///
/// Deliberately never kills a process, even though fanotify does give one
/// here: the process that closed the file (a browser, a download
/// manager, `curl`, ...) merely *wrote* the malicious content, it isn't
/// executing it - killing it would rarely stop anything real and would be
/// a poor experience for what's often a perfectly ordinary program.
/// Quarantining the file itself is both sufficient and non-disruptive.
pub fn run(
    cfg: YaraConfig,
    home: &Path,
    mode: Mode,
    event_tx: tokio::sync::mpsc::UnboundedSender<warden_common::event::DetectionEvent>,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let watch_dirs = cfg.resolve_watch_dirs(home);
    if watch_dirs.is_empty() {
        let e = anyhow::anyhow!("no watch directories resolved");
        let _ = ready_tx.send(Err(e.to_string()));
        return Err(e);
    }

    let (group, compiled_rules, quarantine) = match init(&watch_dirs, &cfg.custom_rules_dir) {
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
    let mut scanner = yara_x::Scanner::new(&compiled_rules);
    info!(?mode, watch_dirs = ?watch_dirs, "yara monitor loop started");

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
            if pid == own_pid {
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

            let results = match scanner.scan_file(&path) {
                Ok(r) => r,
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "yara scan failed (file vanished before we got to it?)");
                    continue;
                }
            };

            let matched: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
            if matched.is_empty() {
                continue;
            }

            let summary = format!("file matched {} YARA rule(s): {}", matched.len(), path.display());
            let detail = matched.join(", ");
            let evt = response::handle_file_only_detection(mode, MODULE, Severity::Critical, &summary, &detail, &path, &quarantine);
            let _ = event_tx.send(evt);
        }
    }
}
