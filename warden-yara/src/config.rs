use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

/// (XDG key, English fallback name) pairs, resolved through
/// `warden_common::xdg::resolve_dir` rather than joined onto `home` as a
/// literal English name - see that module's docs for why a hardcoded
/// name silently misses the real directory on any non-English desktop
/// locale.
const DEFAULT_WATCH_SUBDIRS: &[(&str, &str)] = &[("XDG_DOWNLOAD_DIR", "Downloads"), ("XDG_DESKTOP_DIR", "Desktop"), ("XDG_DOCUMENTS_DIR", "Documents")];

#[derive(Debug, Clone, Deserialize)]
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

// Hand-written, not `#[derive(Default)]` - see the much more severe
// twin of this bug in `warden_ransomware::config::RansomwareConfig` for
// the full explanation. Here a derived `Default` would silently give
// `custom_rules_dir` an empty `PathBuf` instead of
// `/etc/warden/yara-rules` whenever a config.toml has no `[yara]` table
// at all (the normal case) - less severe in practice, since an empty
// path also just fails to exist and custom rules are quietly skipped
// either way, but still wrong: a user who later creates
// `/etc/warden/yara-rules` expecting it to be picked up automatically
// would find it silently ignored.
impl Default for YaraConfig {
    fn default() -> Self {
        Self { watch_dirs: Vec::new(), custom_rules_dir: default_custom_rules_dir() }
    }
}

impl YaraConfig {
    pub fn resolve_watch_dirs(&self, home: &Path) -> Vec<PathBuf> {
        let dirs = if self.watch_dirs.is_empty() {
            DEFAULT_WATCH_SUBDIRS
                .iter()
                .map(|(xdg_key, fallback)| warden_common::xdg::resolve_dir(home, xdg_key, fallback))
                .chain(std::iter::once(PathBuf::from("/tmp")))
                .collect()
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
