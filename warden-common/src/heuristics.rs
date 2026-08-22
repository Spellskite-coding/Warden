/// Filesystem locations nothing legitimate normally executes *from* on a
/// workstation - world-writable scratch space or hidden cache dirs a
/// browser/document exploit would drop a fileless payload into. Shared
/// between the persistence module (flagging a reference to one of these in
/// a newly-added autostart/cron/unit line) and the exec module (flagging a
/// process whose own binary path is one of these), so the list only needs
/// tuning in one place.
pub const SUSPICIOUS_EXEC_PATH_FRAGMENTS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/.cache/"];

pub fn mentions_suspicious_exec_path(text: &str) -> bool {
    SUSPICIOUS_EXEC_PATH_FRAGMENTS.iter().any(|p| text.contains(p))
}

/// Whether `exe_path` is a location nothing legitimate executes from on a
/// workstation: world-writable/hidden scratch space, or the target user's
/// own Downloads folder - the classic drop point for a browser- or
/// document-exploit-delivered fileless payload. Shared between the exec
/// module (checking the tracepoint-reported filename directly) and the
/// network module (checking a `/proc/<pid>/exe` resolved after the fact),
/// so both modules treat "suspicious binary location" identically.
pub fn is_suspicious_exec_location(exe_path: &str, target: &crate::target::TargetUser) -> bool {
    if mentions_suspicious_exec_path(exe_path) {
        return true;
    }
    std::path::Path::new(exe_path).starts_with(&target.downloads_dir)
}
