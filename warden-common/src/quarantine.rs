use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub quarantined_at_unix: u64,
    pub module: String,
    pub pid: i32,
    pub reason: String,
    pub original_path: String,
    /// The file's name inside the quarantine directory, and its stable
    /// identifier: `{timestamp}_{module}_{pid}_{sanitized original path}`,
    /// already unique by construction (see `take`) - a GUI restore action
    /// references an entry by this, not by `original_path` (which isn't
    /// unique across repeated detections of the same file over time).
    pub quarantine_name: String,
    /// Permission bits (mode & 0o7777 - includes setuid/setgid/sticky) and
    /// ownership captured at the moment of quarantine, so `restore` can
    /// put them back explicitly rather than assuming the move preserved
    /// them. It usually would (same-filesystem `rename` never touches
    /// them) but the cross-device fallback (`copy`) does NOT preserve
    /// ownership, and a quarantined *system* binary (a setuid/setgid
    /// helper wrongly flagged, say) coming back with the wrong owner or a
    /// stripped setuid bit would be a real, silent functional regression -
    /// not just "restored", but restored broken.
    #[serde(default)]
    pub original_mode: u32,
    #[serde(default)]
    pub original_uid: u32,
    #[serde(default)]
    pub original_gid: u32,
}

/// Moves files a detection module flagged as malicious out of harm's way and
/// keeps an append-only JSONL manifest so the user (or a future GUI) can
/// review/restore them later. Shared across every detection module so
/// quarantined evidence always lands in one place.
#[derive(Clone)]
pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// Creates (or reuses) the quarantine directory and enforces `0700`
    /// on it explicitly - never trusts the umask, and re-applies the mode
    /// even if the directory already existed, in case it was ever
    /// recreated by hand or restored from a backup with looser
    /// permissions. This directory holds raw malware samples and
    /// ransomware-affected user documents alongside a manifest naming
    /// exactly what was flagged and why; relying on an installer script
    /// to `chmod` it once was found, in review, to leave it world-
    /// readable in any code path that creates it some other way (e.g.
    /// running the daemon binary directly without ever running
    /// `install.sh` first).
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating quarantine dir {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).with_context(|| format!("setting permissions on {}", dir.display()))?;
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// Copies `original`'s bytes to `dest`, deliberately NOT preserving
    /// the source's permission bits the way `fs::copy` does - see
    /// `take`'s call site for why (a live seccomp restriction on setting
    /// setuid/setgid bits). `File::create`'s own default mode
    /// (umask-based, never setuid/setgid) is left as-is on `dest`.
    fn copy_contents_without_preserving_mode(src: &Path, dest: &Path) -> std::io::Result<()> {
        let mut source = fs::File::open(src)?;
        let mut destination = fs::File::create(dest)?;
        std::io::copy(&mut source, &mut destination)?;
        Ok(())
    }

    /// Moves `original` into quarantine and records it in the manifest.
    /// Returns `Ok(None)` if the file was already gone by the time we got to
    /// it (e.g. the process deleted it itself).
    pub fn take(&self, original: &Path, module: &str, pid: i32, reason: &str) -> Result<Option<PathBuf>> {
        // Re-resolve by path and refuse to follow a symlink: the
        // cross-device fallback below uses fs::copy, which (unlike
        // fs::rename) follows symlinks, and would otherwise let anything
        // capable of replacing this path with a symlink make root read and
        // copy an arbitrary target it points to.
        let Ok(meta) = fs::symlink_metadata(original) else {
            return Ok(None);
        };
        if meta.file_type().is_symlink() {
            warn!(
                path = %original.display(),
                pid,
                "path to quarantine is a symlink, refusing to follow it; removing the symlink itself instead"
            );
            let _ = fs::remove_file(original);
            return Ok(None);
        }

        let original_mode = meta.mode() & 0o7777;
        let original_uid = meta.uid();
        let original_gid = meta.gid();

        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let sanitized = original.to_string_lossy().replace('/', "_");
        let quarantine_name = format!("{stamp}_{module}_{pid}_{sanitized}");
        let dest = self.dir.join(&quarantine_name);

        match fs::rename(original, &dest) {
            Ok(()) => {}
            Err(_) => {
                // Not plain `fs::copy`: found live, under the systemd
                // unit's `ProtectSystem=strict` sandbox specifically -
                // each `ReadWritePaths=` entry becomes its own bind
                // mount, so `/tmp` and the quarantine dir now look like
                // different devices to the kernel even on the same
                // physical filesystem, meaning `rename` ALWAYS falls
                // back to this path in practice, not just on a genuinely
                // separate filesystem. `fs::copy` preserves the source's
                // full permission bits, including setuid/setgid - which
                // `RestrictSUIDSGID=true` (same unit file) blocks at the
                // seccomp level as a `chmod`/`fchmod` that tries to SET
                // either bit, so quarantining a live setuid backdoor
                // (exactly warden-privesc's core job) failed outright,
                // repeating forever every poll tick. The quarantined
                // copy never needs to carry the live setuid bit anyway -
                // it's an inert file sitting in a 0700 directory, not
                // meant to be executed - so copying content manually and
                // leaving the destination at `File::create`'s own
                // (umask-based, never-setuid) default mode sidesteps the
                // blocked syscall entirely. The real original mode is
                // still captured in `original_mode` below, unaffected -
                // this only changes what mode the COPY sitting in
                // quarantine gets, not what's reported or later restored.
                Self::copy_contents_without_preserving_mode(original, &dest).with_context(|| format!("copying {} to quarantine", original.display()))?;
                let _ = fs::remove_file(original);
            }
        }

        info!(original = %original.display(), quarantined_as = %dest.display(), module, pid, "file quarantined");

        if let Err(e) = self.append_manifest(&ManifestEntry {
            quarantined_at_unix: stamp,
            module: module.to_string(),
            pid,
            reason: reason.to_string(),
            original_path: original.display().to_string(),
            quarantine_name: quarantine_name.clone(),
            original_mode,
            original_uid,
            original_gid,
        }) {
            error!(error = %e, "failed to write quarantine manifest entry");
        }

        Ok(Some(dest))
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("manifest.jsonl")
    }

    fn append_manifest(&self, entry: &ManifestEntry) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.manifest_path())
            .with_context(|| format!("opening {}", self.manifest_path().display()))?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }

    /// Every file currently sitting in quarantine, for a GUI to list.
    /// Malformed lines are skipped rather than failing the whole read,
    /// same reasoning as `HistoryStore::recent`.
    pub fn list(&self) -> Result<Vec<ManifestEntry>> {
        let data = match fs::read_to_string(self.manifest_path()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.manifest_path().display())),
        };

        let mut entries = Vec::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ManifestEntry>(line) {
                Ok(e) => entries.push(e),
                Err(e) => warn!(error = %e, "skipping malformed quarantine manifest line"),
            }
        }
        Ok(entries)
    }

    /// Moves a quarantined file back to its original location and removes
    /// it from the manifest - the GUI's "restore" action for a false
    /// positive. Refuses to overwrite anything already sitting at the
    /// original path (e.g. the package that shipped it was reinstalled
    /// since) rather than silently clobbering it.
    ///
    /// Uses `renameat2(..., RENAME_NOREPLACE)` for the same-filesystem
    /// case specifically to close a TOCTOU window a review pointed out:
    /// an earlier version checked `dest.exists()` and then called a plain
    /// `rename` afterward, leaving a gap where something could be created
    /// at `dest` in between, silently overwritten by the rename instead
    /// of the "refuses to overwrite" guarantee actually holding. The
    /// kernel checks existence and performs the move as one atomic
    /// operation instead.
    pub fn restore(&self, quarantine_name: &str) -> Result<PathBuf> {
        let entries = self.list()?;
        let Some(entry) = entries.iter().find(|e| e.quarantine_name == quarantine_name) else {
            bail!("no quarantined file with id {quarantine_name:?}");
        };

        let source = self.dir.join(&entry.quarantine_name);
        let dest = PathBuf::from(&entry.original_path);

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }

        let source_parent = source.parent().context("quarantined file path has no parent directory")?;
        let dest_parent = dest.parent().context("restore destination has no parent directory")?;
        let source_name = source.file_name().context("quarantined file path has no file name")?;
        let dest_name = dest.file_name().context("restore destination has no file name")?;
        let source_dirfd = fs::File::open(source_parent).with_context(|| format!("opening {}", source_parent.display()))?;
        let dest_dirfd = fs::File::open(dest_parent).with_context(|| format!("opening {}", dest_parent.display()))?;

        match nix::fcntl::renameat2(&source_dirfd, source_name, &dest_dirfd, dest_name, nix::fcntl::RenameFlags::RENAME_NOREPLACE) {
            Ok(()) => {}
            Err(nix::errno::Errno::EEXIST) => bail!("cannot restore: {} already exists", dest.display()),
            Err(nix::errno::Errno::EXDEV) => {
                // Cross-device: RENAME_NOREPLACE can't help here since
                // there's no single-syscall cross-filesystem move: fall
                // back to a plain existence check + copy. Same residual
                // TOCTOU as before, but only reachable for a quarantine
                // dir/original-path pair spanning filesystems, unlike
                // the common same-filesystem case above.
                if dest.exists() {
                    bail!("cannot restore: {} already exists", dest.display());
                }
                fs::copy(&source, &dest).with_context(|| format!("copying {} back to {}", source.display(), dest.display()))?;
                fs::remove_file(&source).ok();
            }
            Err(e) => return Err(e).with_context(|| format!("restoring {} to {}", source.display(), dest.display())),
        }

        // Explicitly re-applied rather than trusted to have survived the
        // move: a same-filesystem `rename` always preserves them, but this
        // must be correct unconditionally, including the cross-device
        // `copy` fallback above (which does not preserve ownership) - a
        // restored system binary is only actually useful if it comes back
        // with the exact mode (setuid/setgid included) and owner it had
        // before, not just the same bytes.
        let mode = fs::Permissions::from_mode(entry.original_mode);
        fs::set_permissions(&dest, mode).with_context(|| format!("restoring permissions on {}", dest.display()))?;
        nix::unistd::chown(&dest, Some(nix::unistd::Uid::from_raw(entry.original_uid)), Some(nix::unistd::Gid::from_raw(entry.original_gid)))
            .with_context(|| format!("restoring ownership on {}", dest.display()))?;

        let remaining: Vec<&ManifestEntry> = entries.iter().filter(|e| e.quarantine_name != quarantine_name).collect();
        self.rewrite_manifest(&remaining)?;

        info!(
            quarantine_name,
            restored_to = %dest.display(),
            mode = format!("{:o}", entry.original_mode),
            uid = entry.original_uid,
            gid = entry.original_gid,
            "file restored from quarantine"
        );
        Ok(dest)
    }

    /// Atomic rewrite (temp file + rename) rather than editing the
    /// append-only file in place: `restore` is a rare, deliberate action
    /// (not the hot detection path `take`/`append_manifest` are), so the
    /// simplicity of "write the whole new state, then swap it in" is worth
    /// it here, and avoids ever leaving the manifest torn mid-edit.
    fn rewrite_manifest(&self, entries: &[&ManifestEntry]) -> Result<()> {
        let tmp_path = self.dir.join("manifest.jsonl.tmp");
        let mut f = fs::File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        for entry in entries {
            writeln!(f, "{}", serde_json::to_string(entry)?)?;
        }
        f.sync_all().ok();
        fs::rename(&tmp_path, self.manifest_path()).with_context(|| format!("replacing {}", self.manifest_path().display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-quarantine-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn take_then_list_then_restore_round_trips() {
        let qdir = temp_dir("roundtrip");
        let quarantine = Quarantine::new(&qdir).unwrap();

        let src_dir = temp_dir("roundtrip-src");
        fs::create_dir_all(&src_dir).unwrap();
        let original = src_dir.join("payload.sh");
        fs::write(&original, b"echo hi").unwrap();

        let dest = quarantine.take(&original, "yara", -1, "matched a rule").unwrap().unwrap();
        assert!(dest.exists());
        assert!(!original.exists());

        let listed = quarantine.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].original_path, original.display().to_string());

        let restored = quarantine.restore(&listed[0].quarantine_name).unwrap();
        assert_eq!(restored, original);
        assert!(original.exists());
        assert!(!dest.exists());
        assert!(quarantine.list().unwrap().is_empty());

        fs::remove_dir_all(&qdir).ok();
        fs::remove_dir_all(&src_dir).ok();
    }

    /// Regression test for a bug found live during red-team validation:
    /// under the systemd unit's `ProtectSystem=strict` sandbox, `rename`
    /// between `/tmp` and the quarantine dir always falls back to a copy
    /// (separate bind mounts look cross-device to the kernel even on the
    /// same physical filesystem), and plain `fs::copy` propagating a
    /// setuid source's mode bits onto the destination hit
    /// `RestrictSUIDSGID=true` (same unit), making every attempt to
    /// quarantine a live setuid backdoor fail - repeating forever, since
    /// `warden-privesc`'s poll loop retries on every tick. Confirmed here
    /// at the level that actually matters: the quarantined copy's mode
    /// must never carry the setuid/setgid bits the source had, no matter
    /// how permissive the source was.
    #[test]
    fn copy_contents_without_preserving_mode_strips_setuid() {
        let dir = temp_dir("no-setuid-copy");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("setuid_source");
        let dest = dir.join("quarantined_copy");
        fs::write(&src, b"fake elf content").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o6755)).unwrap();

        Quarantine::copy_contents_without_preserving_mode(&src, &dest).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"fake elf content", "content must still be copied correctly");
        let dest_mode = fs::symlink_metadata(&dest).unwrap().mode() & 0o7000;
        assert_eq!(dest_mode, 0, "the quarantined copy must never carry the source's setuid/setgid/sticky bits");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_refuses_to_overwrite_existing_file() {
        let qdir = temp_dir("no-overwrite");
        let quarantine = Quarantine::new(&qdir).unwrap();

        let src_dir = temp_dir("no-overwrite-src");
        fs::create_dir_all(&src_dir).unwrap();
        let original = src_dir.join("payload.sh");
        fs::write(&original, b"echo hi").unwrap();

        let dest = quarantine.take(&original, "yara", -1, "matched a rule").unwrap().unwrap();
        let listed = quarantine.list().unwrap();

        // Something now occupies the original path again.
        fs::write(&original, b"a legitimate new file").unwrap();

        assert!(quarantine.restore(&listed[0].quarantine_name).is_err());
        assert!(dest.exists(), "quarantined copy should be untouched after a refused restore");

        fs::remove_dir_all(&qdir).ok();
        fs::remove_dir_all(&src_dir).ok();
    }
}
