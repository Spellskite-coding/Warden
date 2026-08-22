use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
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

/// Reads the full content behind `fd` - the exact fd the kernel handed
/// back with the `FAN_CLOSE_WRITE` event - via a `dup(2)`'d copy, rather
/// than reopening the file by path afterward.
///
/// A review found the previous code used `fd` only to resolve a path
/// string (via `/proc/self/fd/N`), then discarded it and called
/// `scanner.scan_file(&path)` - a brand-new open-by-path. That's a real
/// TOCTOU window: between the event firing and this reopen, whatever
/// currently sits at that path (attacker-controlled, if they still have
/// write access to the watched directory) is what actually gets scanned,
/// not what was closed. A same-path swap (rename a symlink over it, or
/// replace the content) can make root scan/quarantine something the
/// attacker chose the identity of, or make the actually-malicious
/// content never get scanned at all. Reading through the event's own fd
/// (duplicated so closing our copy doesn't affect the fanotify group's
/// handling of the original) reads the bytes that were ACTUALLY closed,
/// regardless of anything that happens to the path afterward.
fn read_via_fd(fd: BorrowedFd) -> std::io::Result<Vec<u8>> {
    // SAFETY: `dup` on a valid, currently-open fd returns either a fresh
    // fd this call uniquely owns, or -1/errno on failure - no other
    // precondition to uphold. The original `fd` is untouched either way.
    let dup_fd = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative return from dup(2) is a freshly duplicated
    // fd this call uniquely owns - exactly what OwnedFd::from_raw_fd
    // requires.
    let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    let mut file = std::fs::File::from(owned);
    // fanotify hands back the fd already positioned wherever the writer
    // left it (typically EOF right after a close-for-write) - seek back
    // to the start explicitly rather than assuming offset 0.
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
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

            let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap_or_else(|_| PathBuf::from("<unknown>"));

            if !is_under_watch_dirs(&path, &watch_dirs) {
                continue;
            }

            let content = match read_via_fd(fd) {
                Ok(c) => c,
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "reading fanotify event's fd failed");
                    continue;
                }
            };

            let results = match scanner.scan(&content) {
                Ok(r) => r,
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "yara scan failed");
                    continue;
                }
            };

            let matched: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
            if matched.is_empty() {
                continue;
            }

            if warden_common::exceptions::is_exempt(&path) {
                debug!(path = %path.display(), "path is in the exceptions list, not quarantining");
                continue;
            }

            let summary = format!("file matched {} YARA rule(s): {}", matched.len(), path.display());
            let detail = matched.join(", ");
            let evt = response::handle_file_only_detection(mode, MODULE, Severity::Critical, &summary, &detail, &path, &quarantine);
            let _ = event_tx.send(evt);
        }
    }
}
