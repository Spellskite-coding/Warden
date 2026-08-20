use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

/// Every directory a normal `$PATH` would resolve an executable from. A
/// setuid/setgid bit unexpectedly appearing here is treated as a
/// pre-existing binary being tampered with, so the safe Enforce response
/// is to strip the bit, not delete a binary that might otherwise be
/// entirely legitimate (`chmod +s /usr/bin/find`, a well-known GTFOBins
/// privesc technique, doesn't stop `find` from also being the real `find`
/// the system needs).
const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"];

/// World-writable scratch space and the target user's own files - the
/// classic drop point for a backdoored SUID copy of a shell. Nothing
/// legitimate needs a setuid binary here, so the safe Enforce response is
/// to quarantine the file outright.
fn scratch_and_home_dirs(home: &Path) -> Vec<PathBuf> {
    ["/tmp", "/var/tmp", "/dev/shm"].iter().map(PathBuf::from).chain(std::iter::once(home.to_path_buf())).collect()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PrivescConfig {
    /// Directories to watch, in addition to the built-in system defaults
    /// and the target user's own `$HOME`. Treated the same as the scratch/
    /// home set (quarantine on Enforce), not the system bin set. Rarely
    /// needed.
    #[serde(default)]
    pub extra_watch_dirs: Vec<PathBuf>,
}

/// The resolved set of directories to watch, split by which Enforce
/// response applies to a new setuid/setgid grant found under each.
pub struct WatchDirs {
    pub system_bin_dirs: Vec<PathBuf>,
    pub quarantine_dirs: Vec<PathBuf>,
}

impl WatchDirs {
    pub fn is_system_bin_dir(&self, path: &Path) -> bool {
        self.system_bin_dirs.iter().any(|d| path.starts_with(d))
    }

    pub fn all(&self) -> Vec<PathBuf> {
        self.system_bin_dirs.iter().chain(self.quarantine_dirs.iter()).cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.system_bin_dirs.is_empty() && self.quarantine_dirs.is_empty()
    }
}

/// Filters to existing directories and canonicalizes + deduplicates them.
/// On any usr-merge distro (most modern ones), `/bin` and `/sbin` are
/// symlinks to `/usr/bin`/`/usr/sbin` - without this, `SYSTEM_BIN_DIRS`
/// would scan the exact same physical directory twice under two
/// different path strings, producing a duplicate detection for every
/// single file in it (found by testing: `chmod +s /usr/bin/find` was
/// reported and stripped twice, once as `/usr/bin/find` and once as
/// `/bin/find`).
fn existing_only(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    dirs.into_iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(canon) => seen.insert(canon.clone()).then_some(canon),
            Err(e) => {
                debug!(dir = %p.display(), error = %e, "watch dir does not exist, skipping");
                None
            }
        })
        .collect()
}

impl PrivescConfig {
    pub fn resolve_watch_dirs(&self, home: &Path) -> WatchDirs {
        WatchDirs {
            system_bin_dirs: existing_only(SYSTEM_BIN_DIRS.iter().map(PathBuf::from)),
            quarantine_dirs: existing_only(scratch_and_home_dirs(home).into_iter().chain(self.extra_watch_dirs.iter().cloned())),
        }
    }
}
