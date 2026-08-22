use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use nix::fcntl::{Flock, FlockArg};
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

    fn lock_path(&self) -> PathBuf {
        self.dir.join("manifest.lock")
    }

    /// Acquires an exclusive advisory lock (`flock(2)`) shared by every
    /// process that ever touches this quarantine directory's manifest -
    /// `warden` itself, `warden-exec`, `warden-network`, and every
    /// detection module each run in their own process, all sharing this
    /// one directory. A review found a real lost-write race without this:
    /// `restore()` reads the whole manifest, moves the file, then
    /// rewrites the manifest with everything *except* the restored entry.
    /// If another process's `take()` appended a brand new entry in
    /// between that read and that rewrite, the rewrite's full-file
    /// overwrite silently discarded it, even though the file it described
    /// really was sitting in quarantine with no manifest record naming it
    /// afterward. Held for the entire read-modify-write section in
    /// `restore()`, and around every single `append_manifest` call, so
    /// the two paths fully serialize against each other and against
    /// themselves across processes, instead of racing.
    fn lock_manifest(&self) -> Result<Flock<fs::File>> {
        let path = self.lock_path();
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        Flock::lock(f, FlockArg::LockExclusive).map_err(|(_, e)| anyhow::anyhow!("flock on {}: {e}", path.display()))
    }

    fn append_manifest(&self, entry: &ManifestEntry) -> Result<()> {
        let _lock = self.lock_manifest()?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.manifest_path())
            .with_context(|| format!("opening {}", self.manifest_path().display()))?;
        // `.mode(0o600)` above only governs the permissions a *newly
        // created* file gets - confirmed live, the hard way: a manifest
        // that already existed from before this hardening (e.g. an
        // in-place upgrade of a running install) kept its old, looser
        // mode indefinitely, since `open()` ignores the mode argument
        // entirely once `O_CREAT` doesn't actually need to create
        // anything. Re-applied explicitly on every call instead, on the
        // already-open handle (no separate path-based TOCTOU), the same
        // "never trust it survived, always re-assert it" pattern
        // `Quarantine::new` already uses for the directory itself.
        f.set_permissions(fs::Permissions::from_mode(0o600)).with_context(|| format!("hardening permissions on {}", self.manifest_path().display()))?;
        // A single `write_all` on the fully-built line, not `writeln!`
        // directly against `f`: a review found `writeln!` here issues two
        // separate `write(2)` syscalls (the JSON string, then the
        // newline), and while each individual `write(2)` to an
        // `O_APPEND` fd is atomic with respect to other writers, a *pair*
        // of them is not - a concurrent writer's entire line could land
        // in between this one's two writes, corrupting both into one
        // garbled, unparseable line. Building the complete line first and
        // writing it in one call closes that even without the lock above,
        // though the lock alone would already fully serialize this too.
        let mut line = serde_json::to_string(entry)?;
        line.push('\n');
        f.write_all(line.as_bytes())?;
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
        // Held for the whole read-modify-write below (list -> move file
        // -> rewrite manifest), not just the final rewrite - see
        // `lock_manifest`'s doc comment for the lost-write race this
        // closes.
        let _lock = self.lock_manifest()?;
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
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        // Same reasoning as `append_manifest`'s explicit re-chmod: a
        // stale `.tmp` left behind by an interrupted rewrite (a crash
        // between this `open` and the `rename` below, from some earlier
        // run) would otherwise keep whatever permissions it already had,
        // since `.mode(0o600)` only takes effect when `open` actually
        // creates the file.
        f.set_permissions(fs::Permissions::from_mode(0o600)).with_context(|| format!("hardening permissions on {}", tmp_path.display()))?;
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

    /// Regression test for the confirmed lost-write race: many processes
    /// (simulated here with threads - `flock` locks are per open file
    /// description, so a fresh `open()` per `lock_manifest()` call
    /// behaves identically whether it comes from a thread or a separate
    /// process) appending concurrently must never lose or corrupt an
    /// entry, which the old two-syscall `writeln!` plus lack of any
    /// cross-process serialization could do.
    #[test]
    fn concurrent_appends_do_not_lose_or_corrupt_entries() {
        let qdir = temp_dir("concurrent-append");
        let quarantine = std::sync::Arc::new(Quarantine::new(&qdir).unwrap());

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let q = quarantine.clone();
                std::thread::spawn(move || {
                    for j in 0..20 {
                        q.append_manifest(&ManifestEntry {
                            quarantined_at_unix: 0,
                            module: "test".to_string(),
                            pid: i,
                            reason: "concurrency test".to_string(),
                            original_path: format!("/tmp/f-{i}-{j}"),
                            quarantine_name: format!("entry-{i}-{j}"),
                            original_mode: 0,
                            original_uid: 0,
                            original_gid: 0,
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let entries = quarantine.list().unwrap();
        assert_eq!(entries.len(), 8 * 20, "every concurrently appended entry must survive intact and parseable, none lost to interleaving");

        fs::remove_dir_all(&qdir).ok();
    }

    /// Regression test for the specific lost-write scenario a review
    /// found: `restore()`'s read-modify-write (list, move file, rewrite
    /// manifest minus the restored entry) used to have no lock around it,
    /// so a `take()` that appended a brand new entry while a `restore()`
    /// was in flight elsewhere had that append silently discarded by the
    /// restore's stale-snapshot rewrite.
    #[test]
    fn concurrent_take_during_restore_does_not_lose_the_new_entry() {
        let qdir = temp_dir("concurrent-restore-take");
        let quarantine = std::sync::Arc::new(Quarantine::new(&qdir).unwrap());

        let src_dir = temp_dir("concurrent-restore-take-src");
        fs::create_dir_all(&src_dir).unwrap();
        let first = src_dir.join("first.sh");
        fs::write(&first, b"echo hi").unwrap();
        quarantine.take(&first, "yara", -1, "first").unwrap().unwrap();
        let first_id = quarantine.list().unwrap()[0].quarantine_name.clone();

        let restore_handle = {
            let q = quarantine.clone();
            std::thread::spawn(move || q.restore(&first_id))
        };
        let take_handle = {
            let q = quarantine.clone();
            let second = src_dir.join("second.sh");
            std::thread::spawn(move || {
                fs::write(&second, b"echo bye").unwrap();
                q.take(&second, "yara", -1, "second")
            })
        };

        restore_handle.join().unwrap().unwrap();
        take_handle.join().unwrap().unwrap();

        let remaining = quarantine.list().unwrap();
        assert_eq!(remaining.len(), 1, "the concurrently-quarantined second file must still be recorded in the manifest, not silently dropped");
        assert!(remaining[0].original_path.ends_with("second.sh"));

        fs::remove_dir_all(&qdir).ok();
        fs::remove_dir_all(&src_dir).ok();
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
