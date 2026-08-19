use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{error, info, warn};

#[derive(Serialize)]
struct ManifestEntry<'a> {
    quarantined_at_unix: u64,
    module: &'a str,
    pid: i32,
    reason: &'a str,
    original_path: String,
    quarantine_name: String,
}

/// Moves files a detection module flagged as malicious out of harm's way and
/// keeps an append-only JSONL manifest so the user (or a future GUI) can
/// review/restore them later. Shared across every detection module so
/// quarantined evidence always lands in one place.
pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating quarantine dir {}", dir.display()))?;
        Ok(Self { dir: dir.to_path_buf() })
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

        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let sanitized = original.to_string_lossy().replace('/', "_");
        let quarantine_name = format!("{stamp}_{module}_{pid}_{sanitized}");
        let dest = self.dir.join(&quarantine_name);

        match fs::rename(original, &dest) {
            Ok(()) => {}
            Err(_) => {
                fs::copy(original, &dest).with_context(|| format!("copying {} to quarantine", original.display()))?;
                let _ = fs::remove_file(original);
            }
        }

        info!(original = %original.display(), quarantined_as = %dest.display(), module, pid, "file quarantined");

        if let Err(e) = self.append_manifest(&ManifestEntry {
            quarantined_at_unix: stamp,
            module,
            pid,
            reason,
            original_path: original.display().to_string(),
            quarantine_name: quarantine_name.clone(),
        }) {
            error!(error = %e, "failed to write quarantine manifest entry");
        }

        Ok(Some(dest))
    }

    fn append_manifest(&self, entry: &ManifestEntry) -> Result<()> {
        let manifest_path = self.dir.join("manifest.jsonl");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&manifest_path)
            .with_context(|| format!("opening {}", manifest_path.display()))?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }
}
