use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use warden_common::Mode;

/// Only the fields this binary needs are declared - the shared
/// /etc/warden/config.toml also has `[ransomware]` and other tables meant
/// for other binaries, silently ignored here by serde's default
/// (non-strict) field handling.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    pub target_user: String,
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
}
