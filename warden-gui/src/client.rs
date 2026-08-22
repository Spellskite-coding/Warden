use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};
use warden_common::control_protocol::{Request, Response, ScanStatusInfo, StatusInfo, SOCKET_PATH};
use warden_common::history::HistoryRecord;
use warden_common::quarantine::ManifestEntry;

/// One request-response round trip on the control socket. Local Unix
/// socket, sub-millisecond in practice - fast enough to call
/// synchronously from the UI thread rather than pulling in an async
/// runtime just for this.
fn request(req: &Request) -> Result<Response> {
    let mut stream =
        UnixStream::connect(SOCKET_PATH).with_context(|| format!("connecting to {SOCKET_PATH} - is the warden daemon running?"))?;

    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    stream.write_all(line.as_bytes()).context("sending request to warden daemon")?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).context("reading response from warden daemon")?;
    serde_json::from_str(&response_line).context("parsing response from warden daemon")
}

pub fn fetch_history(limit: usize) -> Result<Vec<HistoryRecord>> {
    match request(&Request::History { limit })? {
        Response::History { events } => Ok(events),
        Response::Error { message } => bail!("warden daemon returned an error: {message}"),
        _ => bail!("unexpected response to a History request"),
    }
}

pub fn fetch_status() -> Result<StatusInfo> {
    match request(&Request::Status)? {
        Response::Status(status) => Ok(status),
        Response::Error { message } => bail!("warden daemon returned an error: {message}"),
        _ => bail!("unexpected response to a Status request"),
    }
}

pub fn fetch_quarantine() -> Result<Vec<ManifestEntry>> {
    match request(&Request::ListQuarantine)? {
        Response::Quarantine { entries } => Ok(entries),
        Response::Error { message } => bail!("warden daemon returned an error: {message}"),
        _ => bail!("unexpected response to a ListQuarantine request"),
    }
}

pub fn start_scan(paths: Vec<String>) -> Result<()> {
    match request(&Request::StartScan { paths })? {
        Response::ScanStarted => Ok(()),
        Response::Error { message } => bail!("could not start scan: {message}"),
        _ => bail!("unexpected response to a StartScan request"),
    }
}

pub fn fetch_scan_status() -> Result<ScanStatusInfo> {
    match request(&Request::ScanStatus)? {
        Response::ScanStatus(status) => Ok(status),
        Response::Error { message } => bail!("warden daemon returned an error: {message}"),
        _ => bail!("unexpected response to a ScanStatus request"),
    }
}

// Deliberately no quarantine_file() here: a security review found that
// "only removes trust, can't grant a bypass" was wrong for this action -
// with no path restriction, it could be pointed at Warden's own systemd
// units, config, or binaries, disabling protection with no
// authentication beyond already being the target uid. It goes through
// `pkexec warden --quarantine-file` instead (see `ui.rs`'s
// `run_pkexec_warden`), same reasoning as why exceptions and restore are
// pkexec-only.

// Deliberately no restore_quarantine() here: restoring a file also adds
// an exception for it (see `warden-core`'s `--restore-quarantine`), so
// it goes through `pkexec warden --restore-quarantine` (see `ui.rs`'s
// `run_pkexec_warden`), never through this uid-only-gated socket - same
// reasoning as why exceptions themselves are pkexec-only.
