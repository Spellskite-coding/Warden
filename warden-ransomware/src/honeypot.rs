use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const CANARY_CONTENT: &[u8] =
    b"This file is a Warden canary. Do not delete. Any modification triggers an incident response.\n";

/// Creates the configured decoy files on disk if missing, and returns a set
/// of their canonicalized paths for fast lookup during event handling.
pub fn provision(paths: &[PathBuf]) -> Result<HashSet<PathBuf>> {
    let mut set = HashSet::new();
    for p in paths {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating parent dir for honeypot {}", p.display()))?;
        }
        // symlink_metadata (does not follow the final component) rather
        // than Path::exists()/fs::write's own O_CREAT, which would both
        // follow a symlink planted at `p` and write the fixed canary
        // content through it to whatever it points at.
        match std::fs::symlink_metadata(p) {
            Ok(meta) if meta.file_type().is_symlink() => {
                warn!(path = %p.display(), "honeypot path is a symlink, refusing to provision through it");
            }
            Ok(_) => {}
            Err(_) => {
                std::fs::write(p, CANARY_CONTENT).with_context(|| format!("writing honeypot file {}", p.display()))?;
                info!(path = %p.display(), "provisioned honeypot file");
            }
        }
        let canon = p.canonicalize().with_context(|| format!("canonicalizing honeypot path {}", p.display()))?;
        set.insert(canon);
    }
    Ok(set)
}

pub fn is_honeypot(honeypots: &HashSet<PathBuf>, path: &Path) -> bool {
    match path.canonicalize() {
        Ok(canon) => honeypots.contains(&canon),
        Err(_) => honeypots.contains(path),
    }
}
