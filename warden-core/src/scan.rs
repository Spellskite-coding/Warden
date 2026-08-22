use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tracing::{error, info};
use warden_common::control_protocol::ScanStatusInfo;
use warden_common::event::{DetectionEvent, Severity};
use warden_common::history::HistoryStore;

const MODULE: &str = "yara-scan";

/// Shared state for the single on-demand scan this daemon can run at a
/// time - a live snapshot the control socket reads on every
/// `ScanStatus` request, updated from inside the scan's own blocking
/// task as it walks.
#[derive(Default)]
pub struct ScanState {
    running: AtomicBool,
    files_scanned: AtomicUsize,
    matches_found: AtomicUsize,
}

impl ScanState {
    pub fn snapshot(&self) -> ScanStatusInfo {
        ScanStatusInfo {
            running: self.running.load(Ordering::Relaxed),
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            matches_found: self.matches_found.load(Ordering::Relaxed),
        }
    }

    pub fn try_start(&self) -> bool {
        self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
}

/// Runs one on-demand YARA scan to completion on a blocking thread, then
/// marks `state` as no longer running. Every match is recorded to
/// history exactly like a live detection (so it shows up in the GUI's
/// existing Detections view - no separate "scan results" screen needed)
/// but, deliberately, nothing is ever quarantined: a full-tree audit
/// scan has far less context than live monitoring (arbitrary system
/// files, not just the narrow set of locations nothing legitimate
/// writes to), so its false-positive tolerance has to be much higher.
/// This is meant for a human to review, not to act on automatically.
pub fn spawn(paths: Vec<PathBuf>, custom_rules_dir: PathBuf, history: HistoryStore, state: Arc<ScanState>) {
    tokio::task::spawn_blocking(move || {
        info!(?paths, "on-demand YARA scan started");

        let result = warden_yara::scan_paths(&paths, Some(custom_rules_dir.as_path()), &state.files_scanned, |m| {
            if warden_common::exceptions::is_exempt(&m.path) {
                return;
            }
            state.matches_found.fetch_add(1, Ordering::Relaxed);
            record_match(&history, &m.path, &m.matched_rules);
        });

        if let Err(e) = result {
            error!(error = %e, "on-demand YARA scan failed");
        } else {
            info!(
                files_scanned = state.files_scanned.load(Ordering::Relaxed),
                matches_found = state.matches_found.load(Ordering::Relaxed),
                "on-demand YARA scan complete"
            );
        }
        state.running.store(false, Ordering::SeqCst);
    });
}

fn record_match(history: &HistoryStore, path: &Path, matched_rules: &[String]) {
    let summary = format!("scan found {} YARA rule match(es): {}", matched_rules.len(), path.display());
    let detail = format!("{} (found by an on-demand scan, not quarantined - review manually)", matched_rules.join(", "));
    let evt = DetectionEvent::new(MODULE, Severity::High, summary, detail).with_response(None, vec![path.to_path_buf()], false);
    if let Err(e) = history.record(&evt) {
        error!(id = evt.id, error = %e, "failed to persist scan match to history");
    }
}
