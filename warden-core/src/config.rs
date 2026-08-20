use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use warden_common::target::TargetUser;
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

    #[serde(default)]
    pub privesc: warden_privesc::PrivescConfig,
}

fn default_mode() -> Mode {
    Mode::Monitor
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
        warden_common::target::resolve(&self.target_user)
    }
}
