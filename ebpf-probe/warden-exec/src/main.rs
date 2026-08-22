mod config;

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::maps::{PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use clap::Parser;
use tokio::io::unix::AsyncFd;
use tracing::{error, info, warn};
use warden_common::event::{Mode, Severity};
use warden_common::history::HistoryStore;
use warden_common::notify::Notifier;
use warden_common::quarantine::Quarantine;
use warden_common::response;

const MODULE: &str = "exec";
const MAX_FILENAME: usize = 128;

#[derive(Parser)]
#[command(name = "warden-exec", about = "Fileless-execution detection for Warden, via eBPF")]
struct Args {
    #[arg(short, long, default_value = "/etc/warden/config.toml")]
    config: PathBuf,
    #[arg(short, long)]
    verbose: bool,
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)))
        .init();
}

/// Mirrors `warden-exec-ebpf`'s `ExecEvent { pid: i32, filename: [u8; MAX_FILENAME] }`,
/// a plain repr(C) struct written directly into the ring buffer by the
/// kernel-side program - parsed back out of raw bytes here rather than
/// shared as a common type, since the ebpf crate can't depend on anything
/// requiring std.
fn parse_event(bytes: &[u8]) -> Option<(i32, String)> {
    if bytes.len() < 4 + MAX_FILENAME {
        return None;
    }
    let pid = i32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    let raw = &bytes[4..4 + MAX_FILENAME];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Some((pid, String::from_utf8_lossy(&raw[..end]).into_owned()))
}

/// Resolves `filename` (the exact path the tracepoint reported was passed
/// to `execve(2)`) to its real target, ONLY if `filename` is itself a
/// symlink - `None` otherwise, including for a plain script (a script's
/// `filename` already IS the script path, not a link to follow) and for
/// an ordinary binary invoked directly. See the call site's doc comment
/// for why this deliberately does not consult `/proc/<pid>/exe`.
fn resolve_symlink_target(filename: &str) -> Option<PathBuf> {
    let path = std::path::Path::new(filename);
    if !std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return None;
    }
    std::fs::canonicalize(path).ok()
}

async fn handle_exec(pid: i32, filename: &str, quarantine_path: &str, mode: Mode, quarantine: &Quarantine, notifier: &Notifier, history: &HistoryStore) {
    if warden_common::exceptions::is_exempt(std::path::Path::new(filename))
        || warden_common::exceptions::is_exempt(std::path::Path::new(quarantine_path))
    {
        return;
    }

    let reason = if quarantine_path == filename {
        format!("process executed from a suspicious location: {filename}")
    } else {
        format!("process executed from a suspicious location: {filename} (resolves to {quarantine_path})")
    };
    // Deliberately does NOT skip when the file no longer exists at this
    // path: a process that unlinks its own binary right after exec'ing
    // (classic self-deleting-malware evasion) would otherwise dodge
    // detection entirely just because the quarantine step finds nothing
    // to move - the process itself is still what matters, and
    // response::handle_detection still kills it either way.
    //
    // Quarantines `quarantine_path` (the symlink-resolved real binary
    // when one was available), not the raw tracepoint `filename`:
    // `Quarantine::take` deliberately refuses to follow a symlink (its
    // own separate TOCTOU defense), so quarantining a `filename` that is
    // itself a symlink would only remove the link and leave the actual
    // payload sitting at its target, re-usable via any new symlink.
    let evt = response::handle_detection(
        mode,
        MODULE,
        Severity::High,
        pid,
        &reason,
        vec![std::path::PathBuf::from(quarantine_path)],
        quarantine,
    );
    if let Err(e) = history.record(&evt) {
        error!(id = evt.id, error = %e, "failed to persist detection event to history");
    }
    notifier.notify(evt.severity, &evt.summary, &evt.detail, &evt.id).await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);

    let cfg = config::Config::load(&args.config)?;
    let target = warden_common::target::resolve(&cfg.target_user)?;
    info!(mode = ?cfg.mode, target_user = %cfg.target_user, "loaded config");

    let mut ebpf =
        aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/warden-exec"))).context("loading eBPF object")?;

    let program: &mut TracePoint = ebpf.program_mut("warden_exec").context("warden_exec program missing")?.try_into()?;
    program.load().context("loading tracepoint program")?;
    program.attach("sched", "sched_process_exec").context("attaching to sched_process_exec")?;

    let ring_map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let ring_buf = RingBuf::try_from(ring_map).context("EVENTS is not a ring buffer")?;
    let mut poll = AsyncFd::new(ring_buf).context("registering ring buffer for async polling")?;

    // See `warden-exec-ebpf`'s DROPPED_EVENTS doc comment: turns a
    // previously completely silent ring-buffer-full event loss into an
    // observable warning, checked periodically rather than on every
    // single event (a per-event check would defeat the point of a
    // lock-free ring buffer in the first place).
    let dropped_map = ebpf.take_map("DROPPED_EVENTS").context("DROPPED_EVENTS map missing")?;
    let dropped_events: PerCpuArray<_, u64> = PerCpuArray::try_from(dropped_map).context("DROPPED_EVENTS is not a per-CPU array")?;
    let mut last_dropped: u64 = 0;
    let mut drop_check = tokio::time::interval(std::time::Duration::from_secs(30));

    let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine")).context("initializing quarantine")?;
    let notifier = Notifier::new(target.uid, target.gid);
    let history = HistoryStore::new(std::path::Path::new("/var/lib/warden/history.jsonl")).context("initializing history store")?;
    let own_pid = std::process::id() as i32;

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    info!("exec module ready, watching sched_process_exec");

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            guard_res = poll.readable_mut() => {
                let mut guard = guard_res?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let Some((pid, filename)) = parse_event(&item) else { continue };
                    if pid == own_pid {
                        continue;
                    }
                    // The tracepoint reports the literal path passed to
                    // execve(2) - the kernel never resolves it through a
                    // symlink (see fs/exec.c), so a payload sitting in a
                    // flagged location (/tmp, Downloads, ...) and exec'd
                    // through a symlink placed somewhere unflagged (e.g.
                    // $HOME directly) would otherwise never match.
                    //
                    // A review found the original fix for this (resolving
                    // `/proc/<pid>/exe`, mirroring warden-network) was
                    // wrong in two real ways: (1) for an interpreted
                    // script, `/proc/<pid>/exe` names the INTERPRETER
                    // (`/bin/bash`, `/usr/bin/python3`), not the script -
                    // quarantining that deterministically moves a system
                    // binary out from under every process on the machine,
                    // not the actual payload; (2) it's resolved
                    // asynchronously, well after the tracepoint fired, so
                    // under load `pid` can have already exited and been
                    // reused by an unrelated process by the time this
                    // runs, misattributing both the kill and the
                    // quarantine target.
                    //
                    // Fixed by resolving the symlink question directly
                    // from `filename` itself instead of the live process
                    // image: only follow it if `filename` literally IS a
                    // symlink (script interpreters are never reached this
                    // way, since a script's `filename` is the script
                    // path, not a link), and resolve it synchronously
                    // right here rather than through `pid`'s current
                    // state - no dependency on the process still existing
                    // or still being the same one.
                    let resolved = resolve_symlink_target(&filename);
                    let resolved_str = resolved.as_deref().and_then(|p| p.to_str());
                    let suspicious = warden_common::heuristics::is_suspicious_exec_location(&filename, &target)
                        || resolved_str.is_some_and(|r| warden_common::heuristics::is_suspicious_exec_location(r, &target));
                    if suspicious {
                        let quarantine_path = resolved_str.unwrap_or(&filename);
                        handle_exec(pid, &filename, quarantine_path, cfg.mode, &quarantine, &notifier, &history).await;
                    }
                }
                guard.clear_ready();
            }
            _ = drop_check.tick() => {
                let total: u64 = dropped_events.get(&0, 0).map(|v| v.iter().sum()).unwrap_or(0);
                if total > last_dropped {
                    warn!(
                        dropped_since_start = total,
                        dropped_since_last_check = total - last_dropped,
                        "exec ring buffer was full and dropped event(s) - some process executions were not observed"
                    );
                    last_dropped = total;
                }
            }
            _ = tokio::signal::ctrl_c() => { info!("received SIGINT, shutting down"); return Ok(()); }
            _ = sigterm.recv() => { info!("received SIGTERM, shutting down"); return Ok(()); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_common::target::TargetUser;

    fn test_target() -> TargetUser {
        TargetUser {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/tester"),
            downloads_dir: PathBuf::from("/home/tester/Downloads"),
        }
    }

    #[test]
    fn parses_a_well_formed_event() {
        let mut bytes = vec![0u8; 4 + MAX_FILENAME];
        bytes[0..4].copy_from_slice(&1234i32.to_ne_bytes());
        bytes[4..4 + 8].copy_from_slice(b"/bin/cat");
        let (pid, filename) = parse_event(&bytes).expect("should parse");
        assert_eq!(pid, 1234);
        assert_eq!(filename, "/bin/cat");
    }

    #[test]
    fn rejects_a_truncated_event() {
        assert!(parse_event(&[0u8; 4]).is_none());
    }

    #[test]
    fn flags_tmp_execution() {
        assert!(warden_common::heuristics::is_suspicious_exec_location("/tmp/payload", &test_target()));
    }

    #[test]
    fn flags_downloads_execution() {
        assert!(warden_common::heuristics::is_suspicious_exec_location("/home/tester/Downloads/invoice.exe", &test_target()));
    }

    #[test]
    fn does_not_flag_system_binaries() {
        assert!(!warden_common::heuristics::is_suspicious_exec_location("/usr/bin/whoami", &test_target()));
        assert!(!warden_common::heuristics::is_suspicious_exec_location("/bin/cat", &test_target()));
    }

    #[test]
    fn does_not_flag_documents_execution() {
        assert!(!warden_common::heuristics::is_suspicious_exec_location("/home/tester/Documents/script.sh", &test_target()));
    }

    fn scratch_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-exec-symlink-test-{suffix}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regression test for the red-team-relevant bug this session fixed:
    /// a plain script (no symlink involved) must resolve to `None`, so
    /// `handle_exec` quarantines the script itself - never an interpreter
    /// it happens to run under, which the old `/proc/<pid>/exe`-based
    /// approach would have wrongly substituted in.
    #[test]
    fn plain_script_is_not_treated_as_a_symlink() {
        let dir = scratch_dir("script");
        let script = dir.join("payload.sh");
        std::fs::write(&script, "#!/bin/bash\necho hi\n").unwrap();
        assert_eq!(resolve_symlink_target(script.to_str().unwrap()), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A symlink planted somewhere unflagged, pointing at a real payload
    /// in a flagged location, must resolve to that real target - the
    /// legitimate case this mechanism exists for.
    #[test]
    fn symlink_resolves_to_its_real_target() {
        let dir = scratch_dir("symlink");
        let real_payload = dir.join("evil_payload");
        std::fs::write(&real_payload, b"fake elf content").unwrap();
        let link = dir.join("looks_legit");
        std::os::unix::fs::symlink(&real_payload, &link).unwrap();

        let resolved = resolve_symlink_target(link.to_str().unwrap()).expect("symlink should resolve");
        assert_eq!(resolved, real_payload.canonicalize().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nonexistent_path_is_not_treated_as_a_symlink() {
        assert_eq!(resolve_symlink_target("/nonexistent/warden-exec-test-path"), None);
    }
}
