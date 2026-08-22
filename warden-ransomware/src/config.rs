use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Clone, Deserialize)]
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

// A hand-written `Default` impl, not `#[derive(Default)]`: derived
// `Default` gives every field its type's zero value (0, 0.0, false, an
// empty Vec) regardless of the per-field `#[serde(default = "...")]`
// functions above - fine for `watch_dirs`/`honeypots` (empty really is
// the intended default there), but silently wrong for every numeric
// field. This bit in the worst possible way: `warden-core`'s top-level
// `Config` defaults its whole `ransomware: RansomwareConfig` field via
// `#[serde(default)]` when a config.toml has no `[ransomware]` table at
// all - the normal case, since `install.sh`'s generated config never
// writes one - which calls this `Default` impl, not serde's per-field
// defaults (those only apply when `[ransomware]` is present but missing
// individual keys). With the derived impl, that meant `sample_bytes: 0`
// on every install with a bare config.toml: every content sample read
// 0 bytes, `buf.is_empty()` always short-circuited before entropy was
// even computed, and ransomware detection never actually fired -
// confirmed live, the hard way, chasing what looked like a fanotify
// delivery bug for hours before finding this. `entropy_threshold: 0.0`
// and `burst_file_count: 0` would have been silently wrong the same way.
impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            watch_dirs: Vec::new(),
            honeypots: Vec::new(),
            entropy_threshold: default_entropy_threshold(),
            burst_file_count: default_burst_file_count(),
            burst_window_secs: default_burst_window_secs(),
            sample_bytes: default_sample_bytes(),
            require_directory_baseline: default_true(),
        }
    }
}

/// A workstation's personal data lives under `$HOME`, not on a dedicated
/// mount the way a server's data volume would - so unlike a server
/// deployment, there is no single well-known directory to point at. This is
/// the set of directories most users actually keep documents, media, and
/// downloads in - paired as (XDG key, English fallback name) and resolved
/// through `warden_common::xdg::resolve_dir` rather than joined onto
/// `home` as a literal English name: on any non-English desktop locale
/// the real directories are named in that language (`Bureau`,
/// `Téléchargements`, ... on French), and only the XDG-key lookup finds
/// them. Only the ones that exist are watched.
const DEFAULT_WATCH_SUBDIRS: &[(&str, &str)] =
    &[("XDG_DOCUMENTS_DIR", "Documents"), ("XDG_DESKTOP_DIR", "Desktop"), ("XDG_DOWNLOAD_DIR", "Downloads"), ("XDG_PICTURES_DIR", "Pictures"), ("XDG_VIDEOS_DIR", "Videos"), ("XDG_MUSIC_DIR", "Music")];

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
            self.watch_dirs = DEFAULT_WATCH_SUBDIRS.iter().map(|(xdg_key, fallback)| warden_common::xdg::resolve_dir(home, xdg_key, fallback)).collect();
        } else {
            self.watch_dirs = self.watch_dirs.iter().map(|p| expand_tilde(p, home)).collect();
        }

        // The standalone $HOME-root honeypot's containing folder is, by
        // construction, never one of the six category subdirectories
        // above and doesn't exist on disk yet at this point (unlike
        // every other watch_dirs candidate, which either already exists
        // or is deliberately skipped) - `honeypot::provision` is what
        // actually creates it, moments after this function returns. It's
        // created here too, best-effort and idempotent (a no-op if
        // `provision` already ran once before, e.g. across a restart),
        // specifically so the canonicalize-existence filter just below
        // treats it exactly like the six real ones instead of silently
        // dropping it - without a watch_dirs entry covering it, fanotify
        // events under it would never pass `is_under_watch_dirs`'s
        // prefix filter and this honeypot would silently never fire.
        let home_honeypot = crate::honeypot::home_honeypot_path(home);
        if let Some(home_honeypot_dir) = home_honeypot.parent() {
            if let Err(e) = std::fs::create_dir_all(home_honeypot_dir) {
                warn!(dir = %home_honeypot_dir.display(), error = %e, "could not create the standalone home honeypot directory, it will not be watched this run");
            } else {
                self.watch_dirs.push(home_honeypot_dir.to_path_buf());
            }
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
            // Excludes the home honeypot's own directory from this
            // mapping: it's present in `watch_dirs` only so fanotify
            // covers it (see above), not as an eighth "real" category
            // directory that should itself receive a nested
            // `honeypot_path` honeypot - that would plant a second,
            // redundant decoy INSIDE the "Banque" folder rather than
            // treating it as the standalone honeypot it already is.
            let home_honeypot_dir = home_honeypot.parent().and_then(|p| p.canonicalize().ok());
            self.honeypots = self
                .watch_dirs
                .iter()
                .filter(|d| Some(d.as_path()) != home_honeypot_dir.as_deref())
                .map(|d| crate::honeypot::honeypot_path(d))
                .collect();
            self.honeypots.push(home_honeypot);
        } else {
            self.honeypots = self.honeypots.iter().map(|p| expand_tilde(p, home)).collect();
        }
        self
    }
}
