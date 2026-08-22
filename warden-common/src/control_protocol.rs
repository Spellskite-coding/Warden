use serde::{Deserialize, Serialize};

use crate::history::HistoryRecord;
use crate::quarantine::ManifestEntry;

/// The default path of the GUI-facing control socket - see
/// `warden_core::control` for the server side. A fixed, well-known path
/// rather than something discovered at runtime: there is exactly one
/// Warden daemon per machine, so nothing needs to vary.
pub const SOCKET_PATH: &str = "/run/warden/control.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatusEntry {
    pub name: String,
    pub ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub mode: String,
    pub target_user: String,
    pub modules: Vec<ModuleStatusEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatusInfo {
    pub running: bool,
    pub files_scanned: usize,
    pub matches_found: usize,
}

/// One line of newline-delimited JSON sent from the GUI to the daemon
/// over the control socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    Ping,
    History { limit: usize },
    Status,
    ListQuarantine,
    /// Starts an on-demand YARA audit scan of `paths` (recursive).
    /// Report-only by design - see `warden_yara::scan_paths` - so unlike
    /// restoring a quarantined file or adding an exception, this needs
    /// no stronger authentication than the socket's own uid gate: it
    /// can't bypass or weaken anything, only ever add report-only
    /// entries to history. Refused (`Response::Error`) if a scan is
    /// already running.
    StartScan { paths: Vec<String> },
    /// Whether a scan is currently running, and its progress so far.
    ScanStatus,
    // Deliberately no QuarantineFile here (moved to `warden
    // --quarantine-file`, pkexec-only): a security review found that
    // "only removes trust, can't grant a bypass" was wrong for this one
    // - with no path restriction and no exemption check, it let any
    // same-uid process quarantine Warden's own systemd units, config, or
    // binaries (bypassing their exceptions entirely), disabling
    // protection with no authentication. That's a more powerful bypass
    // than what pkexec already guards for `--add-exception`.
    //
    // Deliberately no RestoreQuarantine here: restoring a file
    // automatically adds an exception for it too (otherwise it would
    // just get re-quarantined within seconds - persistence re-flags a
    // restored UnitDir file via inotify almost immediately, privesc
    // within one 5s poll cycle), which makes "restore" exactly as
    // powerful a bypass as "add an exception". Both go through
    // `warden --restore-quarantine` via pkexec (see `warden-core`'s
    // main.rs and `warden-gui`'s ui.rs), never through this socket -
    // which is gated only on the connecting uid, not a real
    // authentication, so malware already running as the desktop user
    // must not be able to reach either through it.
}

/// One line of newline-delimited JSON sent back from the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    Pong,
    History { events: Vec<HistoryRecord> },
    Status(StatusInfo),
    Quarantine { entries: Vec<ManifestEntry> },
    ScanStarted,
    ScanStatus(ScanStatusInfo),
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_request() {
        let req: Request = serde_json::from_str(r#"{"type":"Ping"}"#).unwrap();
        assert!(matches!(req, Request::Ping));
    }

    #[test]
    fn parses_history_request_with_limit() {
        let req: Request = serde_json::from_str(r#"{"type":"History","limit":25}"#).unwrap();
        assert!(matches!(req, Request::History { limit: 25 }));
    }

    #[test]
    fn rejects_unknown_request_type() {
        let result: std::result::Result<Request, _> = serde_json::from_str(r#"{"type":"Nonsense"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn round_trips_pong_response() {
        let json = serde_json::to_string(&Response::Pong).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Pong));
    }
}
