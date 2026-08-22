use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};
use warden_common::control_protocol::{ModuleStatusEntry, Request, Response, StatusInfo, SOCKET_PATH};
use warden_common::history::HistoryStore;
use warden_common::quarantine::Quarantine;

use crate::scan::ScanState;

/// Whether a process named `binary_name` (as reported by `/proc/<pid>/comm`)
/// is currently running. Used only to report `warden-exec`/`warden-network`'s
/// liveness on the Dashboard - not a security decision like
/// `warden_common::package_manager::is_active`, so a plain comm-name
/// check (spoofable in principle by any process renaming itself) is a
/// fine bar here: worst case a status display is momentarily wrong, not
/// a bypassed detection.
fn is_process_running(binary_name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else { return false };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == binary_name {
                return true;
            }
        }
    }
    false
}

/// GUI-facing control socket - the first of the three GUI prerequisites
/// tracked in PROGRESS.md. A Unix domain socket at a fixed path, restricted
/// to the target desktop user only (owner-only, mode 0600, chowned to
/// their uid/gid) since the daemon itself runs as root but the GUI runs
/// as the logged-in user - no other local user can reach it.
///
/// `status`'s core-module entries are a fixed snapshot taken once at
/// startup, not live-updating: every one of those four modules runs in
/// this same process, and `main`'s own supervision loop already treats
/// any of them ending after startup as fatal to the whole daemon (see
/// `main.rs`), so "some modules degraded, others fine" isn't a state
/// this process can actually be in past startup - if it's still alive
/// and answering pings, its modules are the ones that came up.
/// `warden-exec`/`warden-network` run as separate processes though, so
/// *their* status is checked fresh on every `Status` request instead
/// (see `is_process_running`), and appended to the snapshot per-request.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    history: HistoryStore,
    quarantine: Quarantine,
    status: StatusInfo,
    custom_rules_dir: PathBuf,
    target_uid: u32,
    target_gid: u32,
    target_home: PathBuf,
) -> Result<()> {
    let socket_path = Path::new(SOCKET_PATH);
    if let Some(dir) = socket_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // An unclean previous shutdown can leave the socket file behind, which
    // would otherwise make bind() fail with AddrInUse even though nothing
    // is actually listening on it anymore.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).with_context(|| format!("binding {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).context("setting control socket permissions")?;
    nix::unistd::chown(socket_path, Some(nix::unistd::Uid::from_raw(target_uid)), Some(nix::unistd::Gid::from_raw(target_gid)))
        .context("chowning control socket to target user")?;

    info!(path = SOCKET_PATH, uid = target_uid, "control socket listening");
    let status = Arc::new(status);
    let scan_state: Arc<ScanState> = Arc::new(ScanState::default());

    loop {
        let (stream, _) = listener.accept().await.context("accepting control connection")?;
        let history = history.clone();
        let quarantine = quarantine.clone();
        let status = status.clone();
        let scan_state = scan_state.clone();
        let custom_rules_dir = custom_rules_dir.clone();
        let target_home = target_home.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &history, &quarantine, &status, &scan_state, &custom_rules_dir, &target_home).await {
                warn!(error = %e, "control connection ended with error");
            }
        });
    }
}

/// Generous relative to any real request this protocol ever sends (even
/// `StartScan` with a long list of paths comes nowhere near this), while
/// still a hard, bounded cap - see `read_capped_line`'s doc comment for
/// why an unbounded one is a real problem here.
const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Reads one `\n`-delimited line, refusing to grow past
/// `MAX_REQUEST_LINE_BYTES`. A review found the previous implementation
/// (`tokio::io::AsyncBufReadExt::lines()`) has no such cap: a connected
/// client streaming data with no newline makes it grow the accumulator
/// without bound. Since the control socket is gated only on uid (by
/// design - see this module's other doc comments), any same-uid process
/// can open it, and every detection module runs in this same daemon
/// process/address space, so an OOM triggered this way is likely to take
/// out ALL of Warden's detection, not just this one connection. Reads a
/// byte at a time from the (already internally-buffered) `BufReader`, so
/// this doesn't cost a syscall per byte despite the granularity - fine
/// for a low-volume control protocol, not a hot path.
async fn read_capped_line(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some(String::from_utf8_lossy(&buf).into_owned()) });
        }
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_REQUEST_LINE_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "control request line exceeds max length"));
        }
    }
}

/// A confirmed, live-tested finding: `StartScan` had no restriction at
/// all on which paths it would scan, letting a same-uid caller (the only
/// kind that can ever reach this socket - it's gated on the connecting
/// uid, see this module's own doc comment) make the root daemon read
/// files it can't read itself. Reproduced live: connected as the
/// unprivileged target user, `StartScan(["/root"])` was accepted and
/// completed - `files_scanned` in the following `ScanStatus` confirmed
/// every file under `/root` was actually read - despite `/root` being
/// `0700 root:root`, completely unreadable to that same user directly. A
/// real same-uid-to-root read oracle: even without content ever coming
/// back over the socket, whether a specific file exists or matches a
/// YARA rule leaks through `ScanStatus`/`History`.
///
/// `StartScan`'s whole point is "audit scan of MY OWN files" (per
/// `scan.rs`'s own doc comment), so restricting it to the target user's
/// own `$HOME` closes the oracle without narrowing the feature's actual
/// intended use. `/tmp` is allowed too: it's world-readable/writable
/// already (any local user, this one included, can read whatever's
/// there directly), and YARA's own live monitor already watches it - an
/// on-demand scan of the same directory isn't a new privilege.
fn is_scannable_path(path: &Path, target_home: &Path) -> bool {
    let Ok(canon) = path.canonicalize() else { return false };
    canon.starts_with(target_home) || canon.starts_with("/tmp")
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: UnixStream,
    history: &HistoryStore,
    quarantine: &Quarantine,
    status: &StatusInfo,
    scan_state: &Arc<ScanState>,
    custom_rules_dir: &Path,
    target_home: &Path,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    while let Some(line) = read_capped_line(&mut reader).await.context("reading control request")? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Ping) => Response::Pong,
            Ok(Request::History { limit }) => match history.recent(limit) {
                Ok(events) => Response::History { events },
                Err(e) => Response::Error { message: e.to_string() },
            },
            Ok(Request::Status) => {
                let mut live = status.clone();
                live.modules.push(ModuleStatusEntry { name: "exec".to_string(), ready: is_process_running("warden-exec") });
                live.modules.push(ModuleStatusEntry { name: "network".to_string(), ready: is_process_running("warden-network") });
                Response::Status(live)
            }
            Ok(Request::ListQuarantine) => match quarantine.list() {
                Ok(entries) => Response::Quarantine { entries },
                Err(e) => Response::Error { message: e.to_string() },
            },
            Ok(Request::StartScan { paths }) => {
                if paths.is_empty() {
                    Response::Error { message: "no paths given to scan".to_string() }
                } else if let Some(bad) = paths.iter().find(|p| !is_scannable_path(Path::new(p), target_home)) {
                    Response::Error { message: format!("path not allowed (must be under your home directory or /tmp): {bad}") }
                } else if !scan_state.try_start() {
                    Response::Error { message: "a scan is already running".to_string() }
                } else {
                    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
                    info!(?paths, "on-demand scan requested via control socket");
                    crate::scan::spawn(paths, custom_rules_dir.to_path_buf(), history.clone(), scan_state.clone());
                    Response::ScanStarted
                }
            }
            Ok(Request::ScanStatus) => Response::ScanStatus(scan_state.snapshot()),
            Err(e) => Response::Error { message: format!("invalid request: {e}") },
        };

        let mut out = serde_json::to_string(&response).context("serializing control response")?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await.context("writing control response")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the confirmed live oracle: a scan path
    /// outside the target user's home (and outside /tmp) must be
    /// rejected, even though the daemon itself could technically read
    /// it via CAP_DAC_OVERRIDE.
    #[test]
    fn rejects_paths_outside_home_and_tmp() {
        let home = std::env::temp_dir().join(format!("warden-scan-test-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let inside = home.join("Downloads");
        std::fs::create_dir_all(&inside).unwrap();

        assert!(is_scannable_path(&inside, &home), "a path under the target user's home must be scannable");
        assert!(is_scannable_path(Path::new("/tmp"), &home), "/tmp must be scannable regardless of home");
        assert!(!is_scannable_path(Path::new("/root"), &home), "a path outside home and outside /tmp must be refused");
        assert!(!is_scannable_path(Path::new("/etc"), &home), "a path outside home and outside /tmp must be refused");

        std::fs::remove_dir_all(&home).ok();
    }

    #[tokio::test]
    async fn reads_a_well_formed_line() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut reader = BufReader::new(server);
        client.write_all(b"hello\n").await.unwrap();
        drop(client);
        assert_eq!(read_capped_line(&mut reader).await.unwrap(), Some("hello".to_string()));
    }

    #[tokio::test]
    async fn returns_none_on_clean_eof() {
        let (client, server) = tokio::io::duplex(4096);
        let mut reader = BufReader::new(server);
        drop(client);
        assert_eq!(read_capped_line(&mut reader).await.unwrap(), None);
    }

    /// Regression test for the finding that an unbounded line-accumulator
    /// let a same-uid client OOM the whole daemon (all detection modules
    /// share this process): a client that streams data past
    /// `MAX_REQUEST_LINE_BYTES` with no newline must get an error - and
    /// therefore a closed connection - well before consuming unbounded
    /// memory, not be allowed to keep growing the buffer forever.
    #[tokio::test]
    async fn refuses_a_line_that_exceeds_the_cap() {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let mut reader = BufReader::new(server);
        let writer = tokio::spawn(async move {
            // No newline anywhere in this - exactly the DoS shape: keep
            // streaming without ever completing a line.
            let chunk = vec![b'A'; MAX_REQUEST_LINE_BYTES + 1024];
            let _ = client.write_all(&chunk).await;
        });
        let result = read_capped_line(&mut reader).await;
        assert!(result.is_err(), "a line past the cap must error out instead of growing forever");
        writer.abort();
    }
}
