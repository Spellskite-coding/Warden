use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use tracing::{info, warn};
use warden_common::event::{DetectionEvent, Mode};
use warden_common::quarantine::Quarantine;
use warden_common::response;

use crate::diff;
use crate::heuristics;
use crate::targets::{self, DirWatch, TargetKind};

const MODULE: &str = "persistence";

fn snapshot_baseline(watches: &[DirWatch]) -> HashMap<PathBuf, Vec<String>> {
    let mut baseline = HashMap::new();
    for w in watches {
        for entry in std::fs::read_dir(&w.dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            if w.matching_rule(&name).is_some() {
                let path = w.dir.join(&name);
                if let Some(lines) = diff::read_lines(&path) {
                    baseline.insert(path, lines);
                }
            }
        }
    }
    baseline
}

/// Blocking inotify read/dispatch loop - see `warden_ransomware::fanotify_monitor::run`
/// for the equivalent readiness-gating and retry-backoff pattern this
/// mirrors. Meant to run on a dedicated blocking thread.
pub fn run(
    home: PathBuf,
    target_user: String,
    mode: Mode,
    event_tx: tokio::sync::mpsc::UnboundedSender<DetectionEvent>,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let dir_watches = targets::default_dir_watches(&home, &target_user);
    if dir_watches.is_empty() {
        let e = anyhow::anyhow!("no persistence-relevant directories found to watch under {}", home.display());
        let _ = ready_tx.send(Err(e.to_string()));
        return Err(e);
    }

    let inotify = match Inotify::init(InitFlags::IN_CLOEXEC).context("inotify_init failed") {
        Ok(i) => i,
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let watch_flags =
        AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MODIFY | AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;

    let mut watches: HashMap<WatchDescriptor, DirWatch> = HashMap::new();
    for dw in &dir_watches {
        match inotify.add_watch(&dw.dir, watch_flags) {
            Ok(wd) => {
                info!(dir = %dw.dir.display(), rules = dw.rules.len(), "watching");
                watches.insert(wd, dw.clone());
            }
            Err(e) => warn!(dir = %dw.dir.display(), error = %e, "failed to add inotify watch, skipping"),
        }
    }

    if watches.is_empty() {
        let e = anyhow::anyhow!("failed to establish any inotify watch (all candidate directories rejected)");
        let _ = ready_tx.send(Err(e.to_string()));
        return Err(e);
    }

    let mut baseline = snapshot_baseline(&dir_watches);

    let quarantine = match Quarantine::new(Path::new("/var/lib/warden/quarantine")).context("initializing quarantine") {
        Ok(q) => q,
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let _ = ready_tx.send(Ok(()));
    info!(?mode, watched_dirs = watches.len(), baseline_files = baseline.len(), "persistence monitor loop started");

    const MAX_CONSECUTIVE_READ_FAILURES: u32 = 20;
    let mut consecutive_failures = 0u32;

    loop {
        let events = match inotify.read_events() {
            Ok(ev) => {
                consecutive_failures = 0;
                ev
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_READ_FAILURES {
                    return Err(e).context(format!("inotify read_events failed {consecutive_failures} times in a row, giving up"));
                }
                warn!(error = %e, consecutive_failures, "inotify read_events failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(200 * consecutive_failures.min(10) as u64));
                continue;
            }
        };

        // A single save (even a plain `printf ... > file`) commonly fires
        // several inotify events for the same path - IN_CREATE then
        // IN_MODIFY/IN_CLOSE_WRITE - all queued and returned together in
        // one read_events() batch. Processing each independently would
        // diff the file mid-write for the first event (seeing only
        // whatever had been flushed to disk so far) and again once
        // complete for a later one, producing two different, partially
        // misleading detections for what the user experiences as one
        // change. Since content is always re-read fresh from disk rather
        // than taken from the event itself, collapsing to one processing
        // pass per unique path per batch means that pass sees the final
        // on-disk state, not an intermediate one.
        let mut seen_this_batch = std::collections::HashSet::new();

        for event in events {
            let Some(dw) = watches.get(&event.wd) else { continue };
            // No `name`: the event is on the watched directory itself
            // (rare with the flags we set), not a child entry - nothing to
            // diff.
            let Some(name) = event.name.as_ref() else { continue };
            let Some(rule) = dw.matching_rule(name.as_ref()) else { continue };

            let full_path = dw.dir.join(name);
            if full_path.is_dir() {
                continue;
            }
            if !seen_this_batch.insert(full_path.clone()) {
                continue;
            }

            let old_lines = baseline.get(&full_path).cloned().unwrap_or_default();
            let is_new_file = !baseline.contains_key(&full_path);

            let Some(new_lines) = diff::read_lines(&full_path) else {
                // Vanished again (e.g. an editor's transient temp file
                // matched the rule momentarily) or isn't UTF-8 text.
                // Baseline deliberately left untouched so a subsequent real
                // write still diffs against the last known-good content.
                continue;
            };

            let added = diff::added_lines(&old_lines, &new_lines);

            // A brand-new path read as empty is very likely caught between
            // IN_CREATE firing and the writer actually flushing content
            // (e.g. `printf ... > f` fires IN_CREATE via the O_CREAT open,
            // content lands moments later on IN_CLOSE_WRITE). Committing an
            // empty snapshot to the baseline here would permanently mark
            // this path as "already known" from that point on - so the
            // very next event, the one that actually carries the file's
            // real content, would be treated as an *edit* to a pre-existing
            // file rather than the file's true first sighting, which for a
            // UnitDir target silently skips the Enforce-mode quarantine
            // entirely. Only commit the baseline once there's non-empty
            // content, or once the path was already tracked (an edit
            // legitimately emptying a file is still worth recording as
            // such).
            if !new_lines.is_empty() || !is_new_file {
                baseline.insert(full_path.clone(), new_lines);
            }

            if added.is_empty() {
                continue;
            }

            let (severity, mut reasons) =
                heuristics::score_added_lines(&added).map(|(s, r)| (s.max(rule.base_severity), r)).unwrap_or((rule.base_severity, Vec::new()));

            let summary =
                if is_new_file { format!("new {} appeared: {}", rule.label, full_path.display()) } else { format!("{} changed: {}", rule.label, full_path.display()) };

            if reasons.is_empty() {
                reasons.push(format!("{} new line(s) added, no specific pattern matched - review recommended", added.len()));
            }
            let detail = reasons.join("; ");

            let evt = if rule.kind == TargetKind::UnitDir && is_new_file {
                let evt = response::handle_file_only_detection(mode, MODULE, severity, &summary, &detail, &full_path, &quarantine);
                if evt.action_taken {
                    // The file was moved into quarantine: nothing left at
                    // full_path, so don't keep comparing future writes
                    // there against content that no longer exists on disk.
                    baseline.remove(&full_path);
                }
                evt
            } else {
                warn!(module = MODULE, path = %full_path.display(), severity = %severity, detail = %detail, "persistence change observed (report-only)");
                DetectionEvent::new(MODULE, severity, &summary, &detail)
            };

            let _ = event_tx.send(evt);
        }
    }
}
