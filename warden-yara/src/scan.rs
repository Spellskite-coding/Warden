use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};

use crate::rules;

const MAX_FILES_SCANNED: usize = 200_000;

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
/// escaping the directories the caller actually asked to scan), and the
/// walk stops at `MAX_FILES_SCANNED` rather than running unbounded if a
/// caller points it at something enormous.
pub fn scan_paths(paths: &[PathBuf], custom_rules_dir: Option<&Path>, files_scanned: &AtomicUsize, mut on_match: impl FnMut(ScanMatch)) -> Result<()> {
    let compiled = rules::compile(custom_rules_dir).context("compiling YARA rules for scan")?;
    let mut scanner = yara_x::Scanner::new(&compiled);

    for root in paths {
        if is_excluded(root) {
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
        let Ok(results) = scanner.scan_file(&path) else { continue };
        let matched_rules: Vec<String> = results.matching_rules().map(|r| r.identifier().to_string()).collect();
        if !matched_rules.is_empty() {
            on_match(ScanMatch { path, matched_rules });
        }
    }
}
