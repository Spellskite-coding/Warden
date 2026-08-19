use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::TrustedExecutable;

/// Lets the user exempt specific, known executables (backup tools, disk
/// encryption utilities, `gpg`, ...) from the burst/entropy heuristic, so
/// legitimate bulk encryption of files in a directory that already has a
/// plaintext baseline doesn't get killed.
///
/// Trust is anchored on *both* the executable's path (via `/proc/<pid>/exe`)
/// and a SHA-256 of its current on-disk content: a path match with a
/// mismatching hash is treated as untrusted, so replacing/trojanizing a
/// trusted binary - or a malicious process merely naming itself the same
/// thing - does not grant the bypass. Honeypot detection is never subject to
/// this bypass.
pub struct TrustStore {
    trusted: Vec<TrustedExecutable>,
    cache: HashMap<i32, (bool, Instant)>,
    cache_ttl: Duration,
}

impl TrustStore {
    pub fn new(trusted: Vec<TrustedExecutable>) -> Self {
        Self { trusted, cache: HashMap::new(), cache_ttl: Duration::from_secs(60) }
    }

    pub fn is_trusted(&mut self, pid: i32) -> bool {
        if self.trusted.is_empty() {
            return false;
        }

        let now = Instant::now();
        if let Some((trusted, checked_at)) = self.cache.get(&pid) {
            if now.duration_since(*checked_at) < self.cache_ttl {
                return *trusted;
            }
        }

        let result = self.compute_trust(pid);
        self.cache.insert(pid, (result, now));
        self.cache.retain(|_, (_, checked_at)| now.duration_since(*checked_at) < self.cache_ttl * 4);
        result
    }

    fn compute_trust(&self, pid: i32) -> bool {
        let Ok(exe_path) = fs::read_link(format!("/proc/{pid}/exe")) else {
            return false;
        };

        let Some(entry) = self.trusted.iter().find(|t| t.path == exe_path) else {
            return false;
        };

        let Ok(mut f) = fs::File::open(&exe_path) else {
            return false;
        };

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let Ok(n) = f.read(&mut buf) else { return false };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

        if digest.eq_ignore_ascii_case(&entry.sha256) {
            true
        } else {
            warn!(
                pid,
                path = %exe_path.display(),
                "executable at a configured trusted path has an unexpected hash - NOT trusting it \
                 (binary was replaced/updated since the hash was configured, or this is spoofing)"
            );
            false
        }
    }
}
