use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use warden_common::Mode;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: Mode,

    /// Username of the desktop user Warden protects and notifies. Warden
    /// itself runs as root (fanotify's `FAN_MARK_FILESYSTEM` and killing
    /// arbitrary processes both require it), but root has no personal
    /// files worth watching and no desktop session to pop notifications
    /// into - so unlike root's own $HOME/environment, the user to act on
    /// behalf of must be named explicitly rather than inferred from the
    /// running process.
    pub target_user: String,

    #[serde(default)]
    pub ransomware: warden_ransomware::RansomwareConfig,
}

fn default_mode() -> Mode {
    Mode::Monitor
}

/// The target user's resolved identity: home directory (to know what to
/// watch) and UID (to know which desktop session's D-Bus bus to notify).
pub struct TargetUser {
    pub uid: u32,
    pub home: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let data = std::fs::read_to_string(path).with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&data).with_context(|| format!("parsing config file {}", path.display()))?;
        if cfg.target_user.trim().is_empty() {
            bail!("target_user must be set in {}", path.display());
        }
        Ok(cfg)
    }

    pub fn resolve_target_user(&self) -> Result<TargetUser> {
        let user = nix::unistd::User::from_name(&self.target_user)
            .with_context(|| format!("looking up user {:?}", self.target_user))?
            .with_context(|| format!("no such user: {:?}", self.target_user))?;
        Ok(TargetUser { uid: user.uid.as_raw(), home: user.dir })
    }
}
