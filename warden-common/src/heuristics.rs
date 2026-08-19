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
