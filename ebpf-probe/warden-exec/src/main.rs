mod config;

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use clap::Parser;
use tokio::io::unix::AsyncFd;
use tracing::info;
use warden_common::event::{Mode, Severity};
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

async fn handle_exec(pid: i32, filename: &str, mode: Mode, quarantine: &Quarantine, notifier: &Notifier) {
    let reason = format!("process executed from a suspicious location: {filename}");
    // Deliberately does NOT skip when the file no longer exists at this
    // path: a process that unlinks its own binary right after exec'ing
    // (classic self-deleting-malware evasion) would otherwise dodge
    // detection entirely just because the quarantine step finds nothing
    // to move - the process itself is still what matters, and
    // response::handle_detection still kills it either way.
    let evt = response::handle_detection(
        mode,
        MODULE,
        Severity::High,
        pid,
        &reason,
        vec![std::path::PathBuf::from(filename)],
        quarantine,
    );
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

    let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine")).context("initializing quarantine")?;
    let notifier = Notifier::new(target.uid);
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
                    if warden_common::heuristics::is_suspicious_exec_location(&filename, &target) {
                        handle_exec(pid, &filename, cfg.mode, &quarantine, &notifier).await;
                    }
                }
                guard.clear_ready();
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
        TargetUser { uid: 1000, home: PathBuf::from("/home/tester") }
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
}
