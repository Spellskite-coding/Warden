use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{bail, Result};
use nix::sys::signal::Signal;
use tracing::{error, info};

/// Opens a pidfd for `pid` via the `pidfd_open(2)` syscall - not exposed
/// by the pinned `nix` 0.31 (no `pidfd` module in this version; later
/// ones add one), so called directly through `libc::syscall` using the
/// x86_64 syscall numbers `libc` 0.2 already defines. A pidfd stays
/// bound to the exact process instance it names for as long as the fd
/// itself is held open, even after that PID number is freed and reused
/// by a completely unrelated process - see `stop_then_kill`'s doc
/// comment for why that matters here.
fn pidfd_open(pid: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: SYS_pidfd_open takes a pid_t and a flags word (0 here - no
    // special behavior requested) and returns either a new, valid fd or
    // -1/errno on failure - no other preconditions to uphold.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative return from pidfd_open is a freshly opened
    // fd this call uniquely owns - exactly what OwnedFd::from_raw_fd
    // requires.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Sends `signal` to whatever process `pidfd` was opened against, via
/// `pidfd_send_signal(2)`. Unlike `kill(2)` by raw PID number, this
/// targets the exact process instance the fd names: if that process has
/// already exited, whether or not its PID number has since been reused,
/// the kernel returns `ESRCH` rather than silently signaling whatever
/// unrelated process now happens to hold that number.
fn pidfd_send_signal(pidfd: &OwnedFd, signal: Signal) -> std::io::Result<()> {
    // SAFETY: SYS_pidfd_send_signal takes an open fd, a signal number, a
    // nullable siginfo_t pointer (null = kernel-synthesized info, same
    // as plain kill(2)), and a flags word (0 here). `pidfd` is a valid,
    // live fd for the entire call (borrowed, not consumed by it).
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), signal as i32, std::ptr::null::<u8>(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Neutralizes a suspect process: SIGSTOP first so it cannot act again
/// (write more files, fork, escalate) while the caller quarantines evidence,
/// then SIGKILL. Mirrors the two-step approach proven in RansomShield -
/// stopping before killing closes the window where a process could still
/// do damage between detection and termination.
///
/// Opens a `pidfd` once, right here, and sends BOTH signals through it,
/// not by raw PID number on each call. A plain `kill(pid, sig)` targets
/// whatever process CURRENTLY holds that PID number, not necessarily the
/// one that was actually detected: the kernel recycles PIDs, and under a
/// high fork/exit rate (which an attacker can deliberately induce to
/// widen exactly this window) the detected process can already be gone,
/// its number reassigned to an unrelated one, by the time this runs,
/// particularly between the SIGSTOP and SIGKILL calls a moment apart,
/// where two separate raw-PID `kill()`s could each independently race a
/// PID reuse and end up targeting two DIFFERENT processes without either
/// call ever failing. A pidfd stays bound to the exact process instance
/// for as long as it's held open regardless of PID reuse in the
/// meantime, so both signals here are guaranteed to land on the same
/// process this function opened, or fail cleanly with `ESRCH` rather
/// than ever risking a different, unrelated process that happens to
/// share the old PID number. This does not (and cannot) close every
/// window: the moment between the calling module first observing `pid`
/// (via fanotify or the eBPF ring buffer) and this function's own
/// `pidfd_open` call is inherent to any PID-based detection source and
/// isn't something a pidfd opened only once execution reaches here can
/// retroactively fix - but it does eliminate the previously-real risk of
/// the SIGSTOP and SIGKILL steps drifting onto two different processes.
pub fn stop_then_kill(pid: i32) -> Result<()> {
    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(e) => {
            error!(pid, error = %e, "failed to open pidfd for suspect process (may have already exited)");
            bail!("pidfd_open failed for pid {pid}: {e}");
        }
    };

    if let Err(e) = pidfd_send_signal(&pidfd, Signal::SIGSTOP) {
        error!(pid, error = %e, "failed to SIGSTOP suspect process (may have already exited)");
    }

    match pidfd_send_signal(&pidfd, Signal::SIGKILL) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfd_open_succeeds_for_a_live_process() {
        assert!(pidfd_open(std::process::id() as i32).is_ok());
    }

    #[test]
    fn pidfd_open_fails_for_a_pid_that_does_not_exist() {
        assert!(pidfd_open(i32::MAX).is_err());
    }

    #[test]
    fn stop_then_kill_actually_terminates_a_real_child_process() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("failed to spawn test child");
        let pid = child.id() as i32;

        stop_then_kill(pid).expect("stop_then_kill should succeed on our own live child");

        let status = child.wait().expect("waiting on killed child should succeed");
        assert!(!status.success(), "a SIGKILLed child must not report success");
    }
}
