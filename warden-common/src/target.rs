use std::path::PathBuf;

use anyhow::{Context, Result};

/// A resolved desktop user: home directory (what a filesystem-watching
/// module protects) and UID (whose D-Bus session gets notified). Warden
/// itself always runs as root, which has neither, so every module that
/// needs either resolves this from a configured username rather than
/// inferring it from the running process.
pub struct TargetUser {
    pub uid: u32,
    pub home: PathBuf,
}

pub fn resolve(username: &str) -> Result<TargetUser> {
    let user = nix::unistd::User::from_name(username)
        .with_context(|| format!("looking up user {username:?}"))?
        .with_context(|| format!("no such user: {username:?}"))?;
    Ok(TargetUser { uid: user.uid.as_raw(), home: user.dir })
}
