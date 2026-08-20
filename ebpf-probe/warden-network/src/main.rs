mod config;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use clap::Parser;
use tokio::io::unix::AsyncFd;
use tracing::info;
use warden_common::event::{Mode, Severity};
use warden_common::heuristics::is_suspicious_exec_location;
use warden_common::notify::Notifier;
use warden_common::quarantine::Quarantine;
use warden_common::response;

const MODULE: &str = "network";
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const KIND_CONNECT: u8 = 0;
const KIND_LISTEN: u8 = 1;

#[derive(Parser)]
#[command(name = "warden-network", about = "Outbound-connection and listening-socket detection for Warden, via eBPF")]
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

struct ConnectEvent {
    pid: i32,
    port: u16,
    family: u16,
    kind: u8,
    daddr: [u8; 16],
}

/// Mirrors `warden-network-ebpf`'s `ConnectEvent { pid: i32, port: u16,
/// family: u16, kind: u8, daddr: [u8; 16] }`. repr(C) layout: pid at 0 (4
/// bytes), port at 4 (2), family at 6 (2), kind at 8 (1), daddr at 9 (16,
/// no alignment padding needed since its own alignment is 1) - 25
/// meaningful bytes, then trailing padding up to the struct's 4-byte
/// alignment (28 total). Parsed back out of raw bytes here rather than
/// shared as a common type, since the ebpf crate can't depend on anything
/// requiring std.
fn parse_event(bytes: &[u8]) -> Option<ConnectEvent> {
    if bytes.len() < 25 {
        return None;
    }
    Some(ConnectEvent {
        pid: i32::from_ne_bytes(bytes[0..4].try_into().ok()?),
        port: u16::from_ne_bytes(bytes[4..6].try_into().ok()?),
        family: u16::from_ne_bytes(bytes[6..8].try_into().ok()?),
        kind: bytes[8],
        daddr: bytes[9..25].try_into().ok()?,
    })
}

fn format_daddr(event: &ConnectEvent) -> String {
    match event.family {
        AF_INET => Ipv4Addr::new(event.daddr[0], event.daddr[1], event.daddr[2], event.daddr[3]).to_string(),
        AF_INET6 => Ipv6Addr::from(event.daddr).to_string(),
        other => format!("<unknown address family {other}>"),
    }
}

async fn handle_event(event: &ConnectEvent, exe_path: &str, mode: Mode, quarantine: &Quarantine, notifier: &Notifier) {
    let reason = match event.kind {
        KIND_CONNECT => format!(
            "process at {exe_path} (a suspicious location) opened an outbound connection to {}:{}",
            format_daddr(event),
            event.port
        ),
        KIND_LISTEN => format!("process at {exe_path} (a suspicious location) opened a listening socket on port {}", event.port),
        other => format!("process at {exe_path} (a suspicious location) triggered an unrecognized socket event (kind {other})"),
    };
    // Same reasoning as the exec module: don't skip a vanished binary, the
    // live process is what matters, and response::handle_detection still
    // kills it by pid either way.
    let evt = response::handle_detection(mode, MODULE, Severity::High, event.pid, &reason, vec![PathBuf::from(exe_path)], quarantine);
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
        aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/warden-network"))).context("loading eBPF object")?;

    let program: &mut TracePoint = ebpf.program_mut("warden_connect").context("warden_connect program missing")?.try_into()?;
    program.load().context("loading tracepoint program")?;
    program.attach("sock", "inet_sock_set_state").context("attaching to inet_sock_set_state")?;

    let ring_map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let ring_buf = RingBuf::try_from(ring_map).context("EVENTS is not a ring buffer")?;
    let mut poll = AsyncFd::new(ring_buf).context("registering ring buffer for async polling")?;

    let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine")).context("initializing quarantine")?;
    let notifier = Notifier::new(target.uid);
    let own_pid = std::process::id() as i32;

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    info!("network module ready, watching outbound connection attempts and listening sockets");

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            guard_res = poll.readable_mut() => {
                let mut guard = guard_res?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let Some(event) = parse_event(&item) else { continue };
                    tracing::debug!(pid = event.pid, kind = event.kind, port = event.port, daddr = %format_daddr(&event), "socket event observed");
                    if event.pid == own_pid {
                        continue;
                    }
                    // The tracepoint has no visibility into which binary
                    // the process runs - resolved here from /proc, which
                    // can race a very short-lived process (already exited
                    // by the time we look it up); a vanished
                    // /proc/<pid>/exe just means nothing to flag, not an
                    // error worth logging loudly.
                    let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", event.pid)) else { continue };
                    let exe_path = exe_path.to_string_lossy().into_owned();
                    if is_suspicious_exec_location(&exe_path, &target) {
                        handle_event(&event, &exe_path, cfg.mode, &quarantine, &notifier).await;
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

    #[test]
    fn parses_a_well_formed_connect_event() {
        let mut bytes = vec![0u8; 28];
        bytes[0..4].copy_from_slice(&4242i32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&443u16.to_ne_bytes());
        bytes[6..8].copy_from_slice(&AF_INET.to_ne_bytes());
        bytes[8] = KIND_CONNECT;
        bytes[9..13].copy_from_slice(&[93, 184, 216, 34]);
        let event = parse_event(&bytes).expect("should parse");
        assert_eq!(event.pid, 4242);
        assert_eq!(event.port, 443);
        assert_eq!(event.kind, KIND_CONNECT);
        assert_eq!(format_daddr(&event), "93.184.216.34");
    }

    #[test]
    fn parses_a_well_formed_listen_event() {
        let mut bytes = vec![0u8; 28];
        bytes[0..4].copy_from_slice(&777i32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&4444u16.to_ne_bytes());
        bytes[6..8].copy_from_slice(&AF_INET.to_ne_bytes());
        bytes[8] = KIND_LISTEN;
        let event = parse_event(&bytes).expect("should parse");
        assert_eq!(event.pid, 777);
        assert_eq!(event.port, 4444);
        assert_eq!(event.kind, KIND_LISTEN);
    }

    #[test]
    fn rejects_a_truncated_event() {
        assert!(parse_event(&[0u8; 10]).is_none());
    }

    #[test]
    fn formats_ipv6_addresses() {
        let mut daddr = [0u8; 16];
        daddr[15] = 1;
        let event = ConnectEvent { pid: 1, port: 80, family: AF_INET6, kind: KIND_CONNECT, daddr };
        assert_eq!(format_daddr(&event), "::1");
    }
}
