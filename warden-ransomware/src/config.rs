use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedExecutable {
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of the executable's current content, e.g. the
    /// output of `sha256sum /usr/bin/gpg`.
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RansomwareConfig {
    /// Directories to watch. Left empty (the default), a sensible set of
    /// user data directories under `$HOME` is used - see
    /// `default_watch_dirs`.
    #[serde(default)]
    pub watch_dirs: Vec<PathBuf>,

    /// Decoy files. Any write to one of these is treated as a near-certain
    /// ransomware signal, regardless of entropy or rate. Left empty, one
    /// canary is provisioned per default watch dir.
    #[serde(default)]
    pub honeypots: Vec<PathBuf>,

    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    #[serde(default = "default_burst_file_count")]
    pub burst_file_count: usize,

    #[serde(default = "default_burst_window_secs")]
    pub burst_window_secs: u64,

    #[serde(default = "default_sample_bytes")]
    pub sample_bytes: usize,

    /// See `Detector`: only count a high-entropy write toward the burst
    /// heuristic in a directory previously seen holding ordinary content.
    #[serde(default = "default_true")]
    pub require_directory_baseline: bool,

    #[serde(default)]
    pub trusted_executables: Vec<TrustedExecutable>,
}

fn default_true() -> bool {
    true
}
fn default_entropy_threshold() -> f64 {
    7.5
}
fn default_burst_file_count() -> usize {
    15
}
fn default_burst_window_secs() -> u64 {
    10
}
fn default_sample_bytes() -> usize {
    8192
}

/// A workstation's personal data lives under `$HOME`, not on a dedicated
/// mount the way a server's data volume would - so unlike a server
/// deployment, there is no single well-known directory to point at. This is
/// the set of subdirectories most users actually keep documents, media, and
/// downloads in; only the ones that exist are watched.
const DEFAULT_WATCH_SUBDIRS: &[&str] = &["Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music"];

/// Expands a leading `~` to `home`. Config files are TOML, not a shell, so
/// serde would otherwise deserialize `~/code` as the literal relative path
/// `~/code` - not what a user writing a config by hand expects.
fn expand_tilde(path: &Path, home: &Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

impl RansomwareConfig {
    /// Fills in `watch_dirs`/`honeypots` from `$HOME` when the config left
    /// them empty, otherwise expands `~` and canonicalizes user-supplied
    /// entries. Kept separate from `Deserialize` because the default
    /// depends on the running user's home directory, not just the file.
    /// Canonicalizing matters beyond cosmetics: the runtime event filter
    /// compares a kernel-resolved path against this list with
    /// `starts_with`, which would silently miss everything under a watch
    /// dir that is itself a symlink unless both sides agree on the real
    /// path.
    pub fn resolve_defaults(mut self, home: &Path) -> Self {
        if self.watch_dirs.is_empty() {
            self.watch_dirs = DEFAULT_WATCH_SUBDIRS.iter().map(|d| home.join(d)).collect();
        } else {
            self.watch_dirs = self.watch_dirs.iter().map(|p| expand_tilde(p, home)).collect();
        }

        self.watch_dirs = self
            .watch_dirs
            .iter()
            .filter_map(|p| match p.canonicalize() {
                Ok(canon) => Some(canon),
                Err(e) => {
                    debug!(dir = %p.display(), error = %e, "configured watch dir does not exist, skipping");
                    None
                }
            })
            .collect();

        if self.honeypots.is_empty() {
            self.honeypots = self.watch_dirs.iter().map(|d| d.join(".warden_canary")).collect();
        } else {
            self.honeypots = self.honeypots.iter().map(|p| expand_tilde(p, home)).collect();
        }
        self
    }
}
