use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Global agent operating mode, shared by every detection module: whether a
/// detection only gets logged/notified (safe for tuning thresholds) or also
/// triggers an active response (kill the offending process, quarantine
/// files it touched).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Monitor,
    Enforce,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// One detection, raised by any module (ransomware, persistence, privesc,
/// network, ...) and sent to the core dispatcher for logging, desktop
/// notification, and (later) a GUI event history.
///
/// Response (kill/quarantine) is deliberately NOT decided here: it already
/// happened, synchronously, inside the detecting module itself (via
/// `response::handle_detection`) before this event is even built. Racing an
/// active ransomware process cannot afford the round-trip latency of
/// queuing a "please respond" event through an async channel and waiting
/// for a dispatcher to act on it - every module that needs to act fast
/// calls the shared response helper directly and reports what it already
/// did here, purely for observability.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    /// Stable identifier a future GUI can reference - e.g. from a desktop
    /// notification's click action, to jump straight to this incident's
    /// detail view without re-matching on summary text. Nanosecond-precision
    /// timestamp plus module name: unique enough for how often a single
    /// module can realistically raise events (a collision would only ever
    /// merge two history rows cosmetically, never a security concern), and
    /// needs no shared counter or extra dependency across modules that each
    /// run on their own thread.
    pub id: String,
    pub module: &'static str,
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub pid: Option<i32>,
    pub affected_paths: Vec<PathBuf>,
    pub action_taken: bool,
    pub timestamp_unix: u64,
}

impl DetectionEvent {
    pub fn new(module: &'static str, severity: Severity, summary: impl Into<String>, detail: impl Into<String>) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Self {
            id: format!("{module}-{}", now.as_nanos()),
            module,
            severity,
            summary: summary.into(),
            detail: detail.into(),
            pid: None,
            affected_paths: Vec::new(),
            action_taken: false,
            timestamp_unix: now.as_secs(),
        }
    }

    pub fn with_response(mut self, pid: Option<i32>, affected_paths: Vec<PathBuf>, action_taken: bool) -> Self {
        self.pid = pid;
        self.affected_paths = affected_paths;
        self.action_taken = action_taken;
        self
    }
}
