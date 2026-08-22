use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

/// A single per-machine trust list, shared by every detection module:
/// one entry per binary a human has deliberately exempted, anchored on
/// *both* its path and a SHA-256 of its current on-disk content. Lives
/// next to `config.toml`, but is written only by `warden --add-exception`/
/// `--remove-exception` (a one-shot privileged CLI mode, meant to be
/// invoked via `pkexec` from the GUI) - never by the long-running daemon
/// itself, and never reachable through the GUI's normal control socket.
///
/// That split matters: the control socket is gated only on the
/// connecting *uid* (see `warden_core::control`), which is the right bar
/// for read-only queries and even restoring one already-quarantined
/// file, but "add a standing exemption" is a far more powerful bypass
/// primitive - malware already running as the desktop user (e.g. via a
/// browser exploit) could otherwise silently whitelist itself through
/// that same channel. Requiring a real `pkexec` authentication (the
/// actual root/admin password, not just "is this the right uid") for
/// every exception added is a deliberate, requested defense-in-depth
/// choice, not an oversight to simplify later.
pub const EXCEPTIONS_PATH: &str = "/etc/warden/exceptions.toml";

/// A `File` exception anchors on both its path and a SHA-256 of its
/// current content - the strong, recommended form, immune to an attacker
/// swapping the binary at that path for something malicious.
///
/// A `Directory` exception anchors on path prefix alone, with no
/// integrity check on what's underneath: exempting an entire tree of
/// files that legitimately change on their own (an app's install
/// directory that gets overwritten on every auto-update, so a single
/// file's hash would go stale immediately) is only possible by giving up
/// the hash guarantee for everything under it. It exists for that case
/// specifically - prefer a `File` exception whenever a single stable
/// binary is what actually needs exempting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Exception {
    File { path: String, sha256: String },
    Directory { path: String },
}

impl Exception {
    pub fn path(&self) -> &str {
        match self {
            Exception::File { path, .. } => path,
            Exception::Directory { path, .. } => path,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ExceptionsFile {
    #[serde(default)]
    exceptions: Vec<Exception>,
}

pub fn sha256_of_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn load() -> Result<ExceptionsFile> {
    match fs::read_to_string(EXCEPTIONS_PATH) {
        Ok(data) => toml::from_str(&data).with_context(|| format!("parsing {EXCEPTIONS_PATH}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ExceptionsFile::default()),
        Err(e) => Err(e).with_context(|| format!("reading {EXCEPTIONS_PATH}")),
    }
}

fn save(file: &ExceptionsFile) -> Result<()> {
    if let Some(parent) = Path::new(EXCEPTIONS_PATH).parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let data = toml::to_string_pretty(file).context("serializing exceptions")?;
    fs::write(EXCEPTIONS_PATH, data).with_context(|| format!("writing {EXCEPTIONS_PATH}"))
}

pub fn list() -> Result<Vec<Exception>> {
    Ok(load()?.exceptions)
}

/// Adds (or updates, if the same path was already exempted) an exception
/// for `path`. A directory gets a hash-less `Directory` exception; a file
/// is hashed fresh right now and gets a `File` exception - never trusts a
/// caller-supplied hash. Canonicalizes the path first so `../` tricks or
/// a relative path passed on the CLI can't produce an exception that
/// silently doesn't match what a detection module later resolves via
/// `/proc/<pid>/exe` (always an absolute, canonical path).
pub fn add(path: &Path) -> Result<Exception> {
    let canonical = path.canonicalize().with_context(|| format!("resolving {}", path.display()))?;
    let entry = if canonical.is_dir() {
        Exception::Directory { path: canonical.to_string_lossy().to_string() }
    } else {
        let sha256 = sha256_of_file(&canonical)?;
        Exception::File { path: canonical.to_string_lossy().to_string(), sha256 }
    };

    let mut file = load()?;
    file.exceptions.retain(|e| e.path() != entry.path());
    file.exceptions.push(entry.clone());
    save(&file)?;
    Ok(entry)
}

pub fn remove(path: &Path) -> Result<()> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let path_str = canonical.to_string_lossy().to_string();
    let mut file = load()?;
    file.exceptions.retain(|e| e.path() != path_str);
    save(&file)
}

/// Whether `path` currently matches a configured exception. For a `File`
/// exception, re-hashes the file fresh on every call rather than trusting
/// a cached digest: replacing a legitimately-exempted binary (e.g. a
/// supply-chain compromise, or malware naming itself the same thing at
/// the same path) must invalidate the exception automatically, not leave
/// a standing bypass tied only to a filename. A `File` entry whose path
/// matches but whose hash doesn't is logged and treated as NOT matching
/// that entry - but a `Directory` exception covering the same path (if
/// one exists) can still apply, since it never carried a hash guarantee
/// to begin with. Callers on a hot path (e.g.
/// `warden_ransomware::trust::TrustStore`) are expected to add their own
/// short-lived cache on top of this, not the other way around.
pub fn is_exempt(path: &Path) -> bool {
    let Ok(exceptions) = list() else { return false };
    let path_str = path.to_string_lossy();

    for entry in &exceptions {
        match entry {
            Exception::File { path: exempt_path, sha256 } => {
                if exempt_path.as_str() != path_str {
                    continue;
                }
                match sha256_of_file(path) {
                    Ok(actual) if actual.eq_ignore_ascii_case(sha256) => return true,
                    Ok(_) => warn!(path = %path.display(), "exempted path has an unexpected hash - not exempting it via this entry (binary changed since the exception was added, or this is spoofing)"),
                    Err(_) => {}
                }
            }
            Exception::Directory { path: dir_path } => {
                if path.starts_with(dir_path) {
                    return true;
                }
            }
        }
    }
    false
}

/// Same as `is_exempt`, but resolving the path from a PID's currently
/// executing binary first - for modules (like the ransomware burst
/// detector) that only have a PID, not a path, at detection time.
pub fn is_exempt_pid(pid: i32) -> bool {
    let Ok(exe_path) = fs::read_link(format!("/proc/{pid}/exe")) else { return false };
    is_exempt(&exe_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_file_is_deterministic_and_content_sensitive() {
        let path = std::env::temp_dir().join(format!("warden-exceptions-test-{}.txt", std::process::id()));

        std::fs::write(&path, b"hello world").unwrap();
        let first = sha256_of_file(&path).unwrap();
        let second = sha256_of_file(&path).unwrap();
        assert_eq!(first, second, "hashing the same content twice should give the same digest");
        assert_eq!(first.len(), 64, "sha256 hex digest should be 64 characters");

        std::fs::write(&path, b"different content").unwrap();
        let third = sha256_of_file(&path).unwrap();
        assert_ne!(first, third, "changed content should change the digest");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn exception_variants_round_trip_through_toml() {
        let file = ExceptionsFile {
            exceptions: vec![
                Exception::File { path: "/usr/bin/cat".to_string(), sha256: "a".repeat(64) },
                Exception::Directory { path: "/opt/some-app".to_string() },
            ],
        };
        let serialized = toml::to_string_pretty(&file).expect("serializing exceptions with mixed variants");
        let parsed: ExceptionsFile = toml::from_str(&serialized).expect("parsing exceptions with mixed variants back");
        assert_eq!(parsed.exceptions, file.exceptions);
    }

    #[test]
    fn directory_exception_covers_paths_underneath_it_but_not_siblings() {
        let dir_entry = Exception::Directory { path: "/opt/some-app".to_string() };
        assert!(Path::new("/opt/some-app/bin/tool").starts_with(dir_entry.path()));
        assert!(Path::new("/opt/some-app").starts_with(dir_entry.path()));
        assert!(!Path::new("/opt/some-app-evil/tool").starts_with(dir_entry.path()));
    }
}
