use anyhow::Result;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{error, info};

/// Neutralizes a suspect process: SIGSTOP first so it cannot act again
/// (write more files, fork, escalate) while the caller quarantines evidence,
/// then SIGKILL. Mirrors the two-step approach proven in RansomShield -
/// stopping before killing closes the window where a process could still
/// do damage between detection and termination.
pub fn stop_then_kill(pid: i32) -> Result<()> {
    let target = Pid::from_raw(pid);

    if let Err(e) = signal::kill(target, Signal::SIGSTOP) {
        error!(pid, error = %e, "failed to SIGSTOP suspect process (may have already exited)");
    }

    match signal::kill(target, Signal::SIGKILL) {
        Ok(()) => {
            info!(pid, "killed suspect process");
            Ok(())
        }
        Err(e) => {
            error!(pid, error = %e, "failed to SIGKILL suspect process");
            Err(e.into())
        }
    }
}
