use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::warn;

/// setuid (04000) and setgid (02000) bits.
const SUID_SGID_MASK: u32 = 0o6000;

pub fn has_setuid_or_setgid(mode: u32) -> bool {
    mode & SUID_SGID_MASK != 0
}

/// Removes the setuid and setgid bits from `path` - the safe,
/// non-destructive response to a system binary unexpectedly gaining one:
/// it neutralizes the privilege-escalation vector without deleting or
/// otherwise touching a binary that might, on a known/pre-existing file,
/// still turn out to be a legitimate re-grant. Returns `Ok(false)` without
/// doing anything if the file is already clean or gone.
///
/// Refuses - logged loudly, not silently - to act through a symlink:
/// `chmod(2)` follows symlinks, so blindly chmod'ing a path an attacker
/// just replaced with a symlink could modify permissions on an arbitrary
/// target instead. Same TOCTOU concern `quarantine::Quarantine::take`
/// already guards against for renames; the check-then-act window that
/// remains here is the same accepted risk, not a new one.
pub fn strip_setuid_setgid(path: &Path) -> Result<bool> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    if meta.file_type().is_symlink() {
        warn!(path = %path.display(), "refusing to chmod through a symlink");
        return Ok(false);
    }

    let mut perms = meta.permissions();
    let mode = perms.mode();
    if !has_setuid_or_setgid(mode) {
        return Ok(false);
    }

    perms.set_mode(mode & !SUID_SGID_MASK);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))?;
    Ok(true)
}
