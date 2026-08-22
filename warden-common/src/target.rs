use std::path::PathBuf;

use anyhow::{Context, Result};

/// A resolved desktop user: home directory (what a filesystem-watching
/// module protects) and UID (whose D-Bus session gets notified). Warden
/// itself always runs as root, which has neither, so every module that
/// needs either resolves this from a configured username rather than
/// inferring it from the running process.
pub struct TargetUser {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    /// The user's REAL Downloads directory, resolved once here via
    /// `xdg::resolve_dir` (reads `~/.config/user-dirs.dirs`, falling
    /// back to `home.join("Downloads")`) rather than re-derived from a
    /// hardcoded English name on every check - see `xdg` module docs for
    /// why a hardcoded name is wrong on any non-English desktop locale.
    /// Resolved once at startup, not on every `heuristics` call: the exec
    /// module's suspicious-location check runs on every single process
    /// execution system-wide, a hot enough path that re-reading and
    /// re-parsing a file per event would be wasteful for a value that
    /// never changes for the lifetime of this process.
    pub downloads_dir: PathBuf,
}

pub fn resolve(username: &str) -> Result<TargetUser> {
    let user = nix::unistd::User::from_name(username)
        .with_context(|| format!("looking up user {username:?}"))?
        .with_context(|| format!("no such user: {username:?}"))?;
    let downloads_dir = crate::xdg::resolve_dir(&user.dir, "XDG_DOWNLOAD_DIR", "Downloads");
    Ok(TargetUser { uid: user.uid.as_raw(), gid: user.gid.as_raw(), home: user.dir, downloads_dir })
}
