use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use tracing::{debug, info, warn};
use warden_common::permissions::has_setuid_or_setgid;

const MAX_FILES_SCANNED: usize = 100_000;

fn walk(watch_dirs: &[PathBuf]) -> HashSet<PathBuf> {
    let mut found = HashSet::new();
    let mut scanned = 0usize;

    for root in watch_dirs {
        let mut stack: Vec<PathBuf> = vec![root.clone()];

        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    warn!(dir = %dir.display(), error = %e, "scan: cannot read directory");
                    continue;
                }
            };

            for entry in entries.flatten() {
                if scanned >= MAX_FILES_SCANNED {
                    warn!(limit = MAX_FILES_SCANNED, "scan: file limit reached, stopping early");
                    return found;
                }

                let Ok(meta) = entry.metadata() else { continue };
                let path = entry.path();

                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !meta.is_file() {
                    continue;
                }

                scanned += 1;
                if has_setuid_or_setgid(meta.mode()) {
                    found.insert(path);
                }
            }
        }
    }

    found
}

/// One-time startup scan, establishing which paths already carry
/// setuid/setgid before Warden started watching - without this, every
/// pre-existing system binary (`sudo`, `passwd`, ...) would look
/// indistinguishable from a brand-new grant on the very first poll.
pub fn seed(watch_dirs: &[PathBuf]) -> HashSet<PathBuf> {
    let found = walk(watch_dirs);
    info!(known_suid_sgid = found.len(), "privesc baseline scan complete");
    found
}

/// Repeated periodic scan (same walk, quieter logging - this runs on
/// every poll tick, not just once at startup).
pub fn rescan(watch_dirs: &[PathBuf]) -> HashSet<PathBuf> {
    let found = walk(watch_dirs);
    debug!(current_suid_sgid = found.len(), "privesc rescan complete");
    found
}
