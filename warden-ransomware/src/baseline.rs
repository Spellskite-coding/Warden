use std::io::Read;
use std::path::Path;
use std::{fs, path::PathBuf};

use tracing::{info, warn};

use crate::detector::Detector;
use crate::entropy::shannon_entropy;

const MAX_FILES_SCANNED: usize = 50_000;

/// Walks `root` once at startup, sampling existing files so directories
/// that already hold ordinary content are immediately recognized as having
/// a plaintext baseline. Without this, an agent restart would momentarily
/// "forget" that a directory has real user data, weakening the burst
/// heuristic right when it matters most (right after (re)start).
pub fn seed(detector: &mut Detector, root: &Path, sample_bytes: usize, entropy_threshold: f64) {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut scanned = 0usize;

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "baseline scan: cannot read directory");
                continue;
            }
        };

        for entry in entries.flatten() {
            if scanned >= MAX_FILES_SCANNED {
                warn!(limit = MAX_FILES_SCANNED, "baseline scan: file limit reached, stopping early");
                return;
            }

            let Ok(meta) = entry.metadata() else { continue };
            let path = entry.path();

            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            scanned += 1;
            let Ok(mut f) = fs::File::open(&path) else { continue };
            let mut buf = vec![0u8; sample_bytes];
            let Ok(n) = f.read(&mut buf) else { continue };
            buf.truncate(n);

            if !buf.is_empty() && shannon_entropy(&buf) < entropy_threshold {
                detector.note_plaintext_activity(&path);
            }
        }
    }

    info!(scanned, dir = %root.display(), "baseline scan complete");
}
