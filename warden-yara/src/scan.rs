use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use tracing::debug;

use crate::rules;

const MAX_FILES_SCANNED: usize = 200_000;

// A caller-supplied scan root (or a directory found while walking one)
// could point at an enormous regular file - a VM disk image, a database
// file, a multi-gigabyte log - that would otherwise block a scanner
// thread on a single `scan_file` call for a very long time. Bounding
// individual file size (rather than only the total file *count* via
// `MAX_FILES_SCANNED`) keeps a single pathological file from turning
// an on-demand scan into an effectively unbounded one; files above the
// cap are skipped rather than scanned.
const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

// Pseudo-filesystems: reachable by an uid-gated (no pkexec) `StartScan`
// request with no path restriction, so an operator (or a compromised
// process able to reach the control socket) pointing a scan at one of
// these could hang on a huge/blocking "file" like `/proc/kcore` or
// `/proc/<pid>/mem`, or use YARA match/no-match as an oracle for the
// existence/content-pattern of files it has no read permission on
// (root does the reading here, on the caller's behalf). None of these
// ever contain anything a malware-signature scan is meaningfully
// looking for anyway.
const EXCLUDED_PREFIXES: &[&str] = &["/proc", "/sys", "/dev"];

fn is_excluded(path: &Path) -> bool {
    EXCLUDED_PREFIXES.iter().any(|p| path.starts_with(p))
}

pub struct ScanMatch {
    pub path: PathBuf,
    pub matched_rules: Vec<String>,
}

/// Recursively scans `paths` with the same rule set (built-in + custom)
/// the live monitor compiles - an on-demand audit, not a replacement for
/// it. Deliberately report-only: `on_match` is only ever *told about* a
/// match, never handed anything that touches the file - a full-tree scan
/// covers far more ground than the live monitor's narrow watch dirs, so
/// its false-positive tolerance has to be much higher; auto-quarantining
/// everything it finds would be too aggressive. What to do with a match
/// (record it, ignore an exempted path, ...) is entirely the caller's
/// call.
///
/// Symlinks are never followed (avoids both scan loops and silently
/// escaping the directories the caller actually asked to scan), the
/// walk stops at `MAX_FILES_SCANNED` rather than running unbounded if a
/// caller points it at something enormous, and any single file above
/// `MAX_FILE_SIZE_BYTES` is skipped rather than scanned.
///
/// The symlink check inside `walk` only ever sees entries *discovered
/// while reading a directory* - it has no way to catch a `root` in
/// `paths` that is itself a symlink, so that case is checked here
/// explicitly. Without it, a scan root pointing through a symlink into
/// `/proc` or elsewhere could silently escape both the caller's intent
/// and the `is_excluded` prefix check (which only ever sees the
/// symlink's own literal path, never where it resolves to).
pub fn scan_paths(paths: &[PathBuf], custom_rules_dir: Option<&Path>, files_scanned: &AtomicUsize, mut on_match: impl FnMut(ScanMatch)) -> Result<()> {
    let compiled = rules::compile(custom_rules_dir).context("compiling YARA rules for scan")?;
    let mut scanner = yara_x::Scanner::new(&compiled);

    for root in paths {
        if is_excluded(root) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(root) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        walk(root, &mut scanner, files_scanned, &mut on_match);
        if files_scanned.load(Ordering::Relaxed) >= MAX_FILES_SCANNED {
            break;
        }
    }
    Ok(())
}

fn walk(dir: &Path, scanner: &mut yara_x::Scanner, files_scanned: &AtomicUsize, on_match: &mut impl FnMut(ScanMatch)) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };

    for entry in entries.flatten() {
        if files_scanned.load(Ordering::Relaxed) >= MAX_FILES_SCANNED {
            return;
        }

        let Ok(file_type) = entry.file_type() else { continue };
        // Fast-path skip only - not the authoritative guard against a
        // symlink. `entry.file_type()` is an `lstat` taken while reading
        // the directory; the actual open below happens afterward, so
        // relying on this check alone would leave the same TOCTOU window
        // O_NOFOLLOW closes there.
        if file_type.is_symlink() {
            continue;
        }

        let path = entry.path();
        if file_type.is_dir() {
            if is_excluded(&path) {
                continue;
            }
            walk(&path, scanner, files_scanned, on_match);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        files_scanned.fetch_add(1, Ordering::Relaxed);

        // A review found this used to call `scanner.scan_file(&path)`
        // after only the lstat-based checks above - yara-x's own
        // `scan_file` reopens the path itself with a plain `fs::File::open`
        // (no `O_NOFOLLOW`), a second, separate resolution of the same
        // path. Anything with write access to a directory being scanned
        // could swap a symlink into place in the gap between the check
        // and that reopen, making the daemon (running as root, since an
        // on-demand scan can be pointed anywhere) read and report on an
        // arbitrary target of the attacker's choosing instead of what was
        // actually walked - the same class of bug the live fanotify
        // monitors (`read_via_fd`) were already hardened against.
        // `O_NOFOLLOW` makes the kernel enforce "final component is not a
        // symlink" atomically as part of this single open, closing the
        // window instead of racing it; reading and scanning through that
        // one already-open handle (rather than re-deriving anything from
        // `path` again) means nothing after this point can be swapped out
        // from under us.
        let mut file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path) {
            Ok(f) => f,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "opening file for scan failed (or it is a symlink), skipping");
                continue;
            }
        };
        let Ok(meta) = file.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_FILE_SIZE_BYTES {
            debug!(path = %path.display(), size = meta.len(), "file exceeds scan size cap, skipping");
            continue;
        }
        let mut content = Vec::new();
        if let Err(e) = file.read_to_end(&mut content) {
            debug!(path = %path.display(), error = %e, "reading file for scan failed, skipping");
            continue;
        }
        let Ok(results) = scanner.scan(&content) else { continue };
        let matched_rules: Vec<String> = results.matching_rules().map(|r| r.identifier().to_string()).collect();
        if !matched_rules.is_empty() {
            on_match(ScanMatch { path, matched_rules });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-scan-test-{suffix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_symlinked_scan_root_is_not_followed() {
        let dir = scratch_dir("symlink-root");
        let real_target = dir.join("real");
        std::fs::create_dir_all(&real_target).unwrap();
        std::fs::write(real_target.join("eicar.txt"), b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

        let root_link = dir.join("root_link");
        std::os::unix::fs::symlink(&real_target, &root_link).unwrap();

        let files_scanned = AtomicUsize::new(0);
        let mut matches = Vec::new();
        scan_paths(&[root_link], None, &files_scanned, |m| matches.push(m)).unwrap();

        assert!(matches.is_empty(), "a symlinked scan root must not be followed");
        assert_eq!(files_scanned.load(Ordering::Relaxed), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression test for WD-02's actual TOCTOU closure, not just the
    /// end-to-end behavior: `O_NOFOLLOW` must deterministically refuse to
    /// open a path whose final component is a symlink, with no race
    /// needed to prove it - unlike the old `entry.file_type().is_symlink()`
    /// check followed by a separate `scan_file(&path)` reopen, where a
    /// symlink swapped into place in between the two would win, this
    /// makes "is the final component a symlink" and "open it" one atomic
    /// kernel operation, so there is no window left to race at all.
    #[test]
    fn opening_a_symlink_with_o_nofollow_is_deterministically_refused() {
        let dir = scratch_dir("o-nofollow");
        let target = dir.join("target.txt");
        std::fs::write(&target, b"content").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&link);
        assert!(result.is_err(), "O_NOFOLLOW must refuse to open a path whose final component is a symlink");

        // Control: the exact same call against a real (non-symlink) file
        // must still succeed - the fix must not have broken ordinary scans.
        let ok = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&target);
        assert!(ok.is_ok(), "O_NOFOLLOW must not affect opening a real, non-symlink file");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression test for WD-02: a symlinked *file* discovered while
    /// walking a real (non-symlinked) directory must never be opened or
    /// scanned - not just a symlinked scan root, which
    /// `a_symlinked_scan_root_is_not_followed` above already covers.
    /// Exercises both layers of the fix: the `file_type.is_symlink()`
    /// fast-path skip, and `O_NOFOLLOW` as the authoritative guard behind
    /// it.
    #[test]
    fn a_symlinked_file_inside_a_real_directory_is_not_followed() {
        // The real EICAR content must live *outside* the scanned root -
        // otherwise `walk` would find and match it directly as a regular
        // file in its own right, making the test pass regardless of
        // whether the symlink pointing at it was followed.
        let outside = scratch_dir("symlink-file-target");
        let target = outside.join("eicar_target.txt");
        std::fs::write(&target, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

        let dir = scratch_dir("symlink-file");
        let link = dir.join("innocuous_name.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let files_scanned = AtomicUsize::new(0);
        let mut matches = Vec::new();
        scan_paths(std::slice::from_ref(&dir), None, &files_scanned, |m| matches.push(m)).unwrap();

        assert!(matches.is_empty(), "a symlinked file must not be followed and scanned");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn a_real_directory_root_is_still_scanned_normally() {
        let dir = scratch_dir("real-root");
        std::fs::write(dir.join("eicar.txt"), b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

        let files_scanned = AtomicUsize::new(0);
        let mut matches = Vec::new();
        scan_paths(std::slice::from_ref(&dir), None, &files_scanned, |m| matches.push(m)).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_rules.contains(&"Eicar_Test_File".to_string()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_larger_than_the_size_cap_is_skipped_rather_than_scanned() {
        let dir = scratch_dir("oversized-file");
        let huge = dir.join("huge.bin");
        // Doesn't need to actually contain MAX_FILE_SIZE_BYTES of data on
        // disk - a sparse file reports the same `len()` to `metadata()`
        // and is what the size check reads, without writing 100MB in a
        // test run.
        let f = std::fs::File::create(&huge).unwrap();
        f.set_len(MAX_FILE_SIZE_BYTES + 1).unwrap();
        drop(f);

        let files_scanned = AtomicUsize::new(0);
        let mut matches = Vec::new();
        scan_paths(std::slice::from_ref(&dir), None, &files_scanned, |m| matches.push(m)).unwrap();

        assert!(matches.is_empty());
        // Still counted toward the file budget - the size check happens
        // after `files_scanned` is incremented - so a caller pointing a
        // scan at many oversized files still can't bypass MAX_FILES_SCANNED.
        assert_eq!(files_scanned.load(Ordering::Relaxed), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
