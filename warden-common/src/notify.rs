use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::event::Severity;

/// Pops a desktop notification via the standard freedesktop D-Bus
/// Notifications service (GNOME Shell, dunst, mako, KDE Plasma, ...), and
/// listens for the user clicking it.
///
/// Warden runs as root, but the notification has to land on a logged-in
/// user's desktop session - not root's, and *not* reachable by simply
/// connecting to the target user's session bus as root either: a root
/// process can open `/run/user/<uid>/bus` regardless of its 0700
/// permissions (DAC checks don't apply to root), but dbus-daemon accepts
/// the SASL handshake from a foreign uid and then silently drops the
/// connection right as it would process the client's `Hello` call,
/// without ever replying - confirmed by strace on two different
/// dbus-daemon versions, so this is deliberate hardening, not a bug to
/// route around inside zbus. The only thing that reliably works is
/// connecting *as* the target uid, so this instead spawns
/// `warden-notify-helper` with its privileges dropped to the target
/// user's uid/gid, and talks to it over stdin/stdout as
/// newline-delimited JSON.
pub struct Notifier {
    target_uid: u32,
    target_gid: u32,
    child: Arc<Mutex<Option<ChildHandle>>>,
}

struct ChildHandle {
    stdin: tokio::process::ChildStdin,
    /// Signals the background reaper task (spawned in `spawn_helper`) to
    /// kill and wait on the child. A `oneshot::Sender` rather than keeping
    /// the `Child` here directly: the `Child` itself lives inside that
    /// task instead, so it is *always* under an active `wait()`/`select!`
    /// and therefore always reaped the moment it exits - whether that's
    /// because the parent asked it to die (this channel) or because it
    /// died on its own (killed externally, crashed, ...). Keeping the
    /// `Child` here and only calling `wait()` on the narrow "we detected a
    /// broken pipe" path would leave it unreaped for as long as no further
    /// notification happens to be sent afterward.
    kill_tx: tokio::sync::oneshot::Sender<()>,
}

#[derive(serde::Serialize)]
struct NotifyRequest<'a> {
    urgency: u8,
    title: &'a str,
    body: &'a str,
    incident_id: &'a str,
}

#[derive(serde::Deserialize)]
struct ActionInvoked {
    incident_id: String,
    action: String,
}

/// Locates `warden-notify-helper`: first next to the currently running
/// binary (the layout every Warden binary is installed in), falling
/// back to a bare name resolved via `PATH` so a non-standard install
/// layout still works rather than hard failing.
fn helper_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("warden-notify-helper")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("warden-notify-helper"))
}

fn spawn_helper(target_uid: u32, target_gid: u32) -> Result<ChildHandle> {
    // All three of setgroups/setgid/setuid happen in a single `pre_exec`
    // closure, in that exact order, rather than mixing `.uid()`/`.gid()`
    // (which handle the primary identity) with a separate `pre_exec` for
    // groups (which used to only call `setgroups`): live testing hit
    // `EPERM` from this, root-caused to ordering - `setgroups`/`setgid`
    // both need `CAP_SETGID` in the *effective* set, which is only
    // guaranteed to still be there before the uid is dropped from root.
    // `.uid()`'s own internal ordering relative to a separately-attached
    // `pre_exec` isn't something to rely on; doing all three explicitly,
    // in the one closure, in the well-known-correct order (groups, then
    // gid, then uid - reversing the last two is the classic way to
    // silently keep the*old* gid), removes the ambiguity entirely.
    // `pre_exec` runs in the child between fork and exec, single-
    // threaded at that point, so plain syscalls here are safe despite
    // the `unsafe` on the API.
    let mut command = Command::new(helper_path());
    // systemd sets NOTIFY_SOCKET in this (root) process's own environment
    // for `sd_notify(3)`-based readiness signaling (see main.rs's
    // `READY=1` gating). `Command::spawn` inherits the parent's
    // environment by default, so without this the child - about to have
    // its privileges dropped to the target *user* - would otherwise
    // inherit a live path to systemd's notification socket for this
    // root-owned unit. An unprivileged process holding that would be
    // able to send this service's systemd unit spoofed `WATCHDOG=1`/
    // `READY=1`/`STOPPING=1` datagrams - e.g. defeating a watchdog timer
    // meant to catch this same daemon hanging. `warden-notify-helper`
    // itself never needs it (it never calls sd_notify), and stripping it
    // here also means nothing it in turn execs (`warden-gui`) ever sees
    // it either.
    command.env_remove("NOTIFY_SOCKET");
    unsafe {
        command.as_std_mut().pre_exec(move || {
            nix::unistd::setgroups(&[nix::unistd::Gid::from_raw(target_gid)]).map_err(std::io::Error::from)?;
            nix::unistd::setgid(nix::unistd::Gid::from_raw(target_gid)).map_err(std::io::Error::from)?;
            nix::unistd::setuid(nix::unistd::Uid::from_raw(target_uid)).map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("spawning warden-notify-helper")?;

    let stdin = child.stdin.take().context("helper has no stdin")?;
    let stdout = child.stdout.take().context("helper has no stdout")?;
    tokio::spawn(read_clicks(stdout));

    // A review found this daemon spawns `warden-notify-helper` but never
    // unconditionally reaps it - only when a subsequent `notify()` call
    // happened to detect a broken stdin pipe, which never happens at all
    // if nothing gets detected again afterward. This root daemon must
    // never leave a child process it spawned as a zombie, independent of
    // its own later activity - so `child` moves into its own task here,
    // which owns it for its entire remaining lifetime and reaps it either
    // when it exits on its own or when asked to via `kill_tx`.
    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            status = child.wait() => match status {
                Ok(status) => info!(%status, "warden-notify-helper exited"),
                Err(e) => warn!(error = %e, "waiting on warden-notify-helper failed"),
            },
            _ = kill_rx => {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
    });

    Ok(ChildHandle { stdin, kill_tx })
}

/// Reads `ActionInvoked` lines the helper prints when the target user
/// clicks a notification, for as long as the helper process lives.
async fn read_clicks(stdout: tokio::process::ChildStdout) {
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match serde_json::from_str::<ActionInvoked>(&line) {
                Ok(evt) => {
                    // TODO(GUI): once the warden-gui binary exists, launch
                    // it here, e.g. `std::process::Command::new("warden-gui").arg("--incident").arg(&evt.incident_id).spawn()`.
                    // warden-notify-helper already launched warden-gui
                    // itself (it runs as the target user, unlike this
                    // root process) - this is purely for observability.
                    info!(incident_id = evt.incident_id, action = evt.action, "notification clicked");
                }
                Err(e) => warn!(error = %e, "failed to parse click event from warden-notify-helper"),
            },
            Ok(None) => break, // helper exited
            Err(e) => {
                error!(error = %e, "reading from warden-notify-helper stdout");
                break;
            }
        }
    }
}

impl Notifier {
    pub fn new(target_uid: u32, target_gid: u32) -> Self {
        Self { target_uid, target_gid, child: Arc::new(Mutex::new(None)) }
    }

    /// Best-effort: a user who is not currently logged into a graphical
    /// session (the helper can't reach a session bus yet, or no
    /// notification daemon is registered on it) must never take the
    /// agent down over this, so failures are only logged. `incident_id`
    /// should be a `DetectionEvent::id` - clicking the notification's
    /// "View details" action is correlated back to it (inside the
    /// helper) so a future GUI can jump straight to that incident
    /// instead of just its home screen.
    pub async fn notify(&self, severity: Severity, summary: &str, body: &str, incident_id: &str) {
        let urgency: u8 = match severity {
            Severity::Info | Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High | Severity::Critical => 2,
        };
        let title = format!("Warden — {severity}: {summary}");
        let req = NotifyRequest { urgency, title: &title, body, incident_id };
        let mut line = match serde_json::to_string(&req) {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "failed to serialize notify request");
                return;
            }
        };
        line.push('\n');

        let mut guard = self.child.lock().await;
        if guard.is_none() {
            match spawn_helper(self.target_uid, self.target_gid) {
                Ok(handle) => *guard = Some(handle),
                Err(e) => {
                    // `{:#}` (anyhow's alternate Display), not `%e`/`{}`:
                    // the latter only prints the outermost `.context()`
                    // message, silently dropping the actual underlying
                    // OS error - which is the one piece of information
                    // that would actually explain a failure like this.
                    warn!(error = format!("{e:#}"), uid = self.target_uid, "failed to spawn warden-notify-helper");
                    return;
                }
            }
        }

        let Some(handle) = guard.as_mut() else { return };
        if let Err(e) = handle.stdin.write_all(line.as_bytes()).await {
            warn!(error = %e, uid = self.target_uid, "warden-notify-helper pipe broken, will respawn on next notification");
            if let Some(handle) = guard.take() {
                let _ = handle.kill_tx.send(());
            }
        }
    }
}
