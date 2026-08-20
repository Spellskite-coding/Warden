use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

const DEFAULT_WATCH_SUBDIRS: &[&str] = &["Downloads", "Desktop", "Documents"];

#[derive(Debug, Clone, Deserialize, Default)]
pub struct YaraConfig {
    /// Directories to scan newly-written files in. Left empty (the
    /// default), the target user's Downloads/Desktop/Documents plus
    /// `/tmp` are used - the locations a browser- or document-exploit-
    /// delivered payload actually lands in.
    #[serde(default)]
    pub watch_dirs: Vec<PathBuf>,

    /// Directory of additional `*.yar` rule files, compiled alongside the
    /// built-in set.
    #[serde(default = "default_custom_rules_dir")]
    pub custom_rules_dir: PathBuf,
}

fn default_custom_rules_dir() -> PathBuf {
    PathBuf::from("/etc/warden/yara-rules")
}

impl YaraConfig {
    pub fn resolve_watch_dirs(&self, home: &Path) -> Vec<PathBuf> {
        let dirs = if self.watch_dirs.is_empty() {
            DEFAULT_WATCH_SUBDIRS.iter().map(|d| home.join(d)).chain(std::iter::once(PathBuf::from("/tmp"))).collect()
        } else {
            self.watch_dirs.clone()
        };

        dirs.into_iter()
            .filter_map(|p| match p.canonicalize() {
                Ok(canon) => Some(canon),
                Err(e) => {
                    debug!(dir = %p.display(), error = %e, "yara watch dir does not exist, skipping");
                    None
                }
            })
            .collect()
    }
}
