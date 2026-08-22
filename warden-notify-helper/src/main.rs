use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};
use zbus::zvariant::Value;
use zbus::{Connection, ConnectionBuilder, Proxy};

/// Unprivileged helper spawned by the root `warden` daemon, with its
/// privileges dropped to the target desktop user's uid/gid before exec
/// (see `warden_common::notify::Notifier::new`). It exists because a
/// root process cannot complete a D-Bus session-bus handshake with a
/// bus it does not own: dbus-daemon accepts the SASL `AUTH EXTERNAL`
/// from a foreign uid (root can open the 0700 socket regardless of
/// filesystem permissions) but then silently drops the connection right
/// as it would process the client's `Hello` call, without ever
/// replying - confirmed by side-by-side strace comparison against a
/// same-uid connection on two different dbus-daemon versions, so this
/// is deliberate hardening in dbus-daemon, not a bug to work around in
/// zbus. Running this binary *as* the target uid sidesteps it entirely.
///
/// Talks to its parent over stdin/stdout as newline-delimited JSON:
/// reads `NotifyRequest`s on stdin, writes `ActionInvoked`s to stdout
/// whenever the user clicks a notification this process raised.
const CORRELATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Deserialize)]
struct NotifyRequest {
    urgency: u8,
    title: String,
    body: String,
    incident_id: String,
}

#[derive(Debug, Serialize)]
struct ActionInvoked {
    incident_id: String,
    action: String,
}

fn init_tracing() {
    // stdout is the click-correlation protocol channel to the parent -
    // logs must never land there.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();
}

async fn connect() -> Result<Connection> {
    let uid = nix::unistd::getuid().as_raw();
    let address = format!("unix:path=/run/user/{uid}/bus");
    ConnectionBuilder::address(address.as_str())?.build().await.context("connecting to own session D-Bus")
}

async fn send_notification(connection: &Connection, req: &NotifyRequest) -> Result<u32> {
    let expire_ms: i32 = if req.urgency == 2 { 0 } else { 10_000 };
    let mut hints: HashMap<&str, Value> = HashMap::new();
    hints.insert("urgency", Value::from(req.urgency));
    let actions = vec!["default", "View details"];

    let reply = connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &("Warden EDR", 0u32, "security-high-symbolic", req.title.as_str(), req.body.as_str(), actions, hints, expire_ms),
        )
        .await
        .context("calling Notify over D-Bus")?;
    reply.body().deserialize().context("parsing Notify reply")
}

/// Owns the send-side connection: reads one `NotifyRequest` per stdin
/// line, sends it, and records the notification id -> incident id
/// correlation for the listener task to resolve later. Reconnects
/// lazily (on the next request) if the cached connection has gone bad,
/// rather than failing the whole process over a transient disconnect
/// (e.g. the user logs out and back in).
async fn run_sender(correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>>) -> Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut connection: Option<Connection> = None;

    while let Some(line) = lines.next_line().await.context("reading request from stdin")? {
        if line.trim().is_empty() {
            continue;
        }
        let req: NotifyRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to parse notify request from parent");
                continue;
            }
        };

        if connection.is_none() {
            connection = connect().await.map_err(|e| warn!(error = %e, "reconnecting to session D-Bus")).ok();
        }
        let Some(conn) = connection.as_ref() else { continue };

        match send_notification(conn, &req).await {
            Ok(notif_id) => {
                if let Ok(mut map) = correlations.lock() {
                    let now = Instant::now();
                    map.retain(|_, (_, added)| now.duration_since(*added) < CORRELATION_TTL);
                    map.insert(notif_id, (req.incident_id.clone(), now));
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to show desktop notification, dropping cached connection");
                connection = None;
            }
        }
    }
    Ok(())
}

/// Background task: keeps a persistent connection to listen for
/// `ActionInvoked` (the user clicked a notification), reconnecting with
/// a fixed backoff on any failure - mirrors the retry loop this
/// replaced in `warden_common::notify`, just now running at the right
/// uid to actually succeed.
async fn run_listener(correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>>) {
    loop {
        if let Err(e) = run_listener_once(&correlations).await {
            debug!(error = %e, "notification action listener disconnected, retrying");
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

async fn run_listener_once(correlations: &Arc<Mutex<HashMap<u32, (String, Instant)>>>) -> Result<()> {
    let connection = connect().await?;
    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await
    .context("building Notifications proxy")?;

    let mut stream = proxy.receive_signal("ActionInvoked").await.context("subscribing to ActionInvoked")?;
    info!("listening for desktop notification clicks");

    let mut stdout = tokio::io::stdout();
    while let Some(msg) = stream.next().await {
        let Ok((notif_id, action)) = msg.body().deserialize::<(u32, String)>() else { continue };
        let incident = correlations.lock().ok().and_then(|mut map| map.remove(&notif_id));
        let Some((incident_id, _)) = incident else { continue };

        launch_gui(&incident_id);

        let out = ActionInvoked { incident_id, action };
        if let Ok(mut line) = serde_json::to_string(&out) {
            line.push('\n');
            let _ = stdout.write_all(line.as_bytes()).await;
            let _ = stdout.flush().await;
        }
    }
    Ok(())
}

/// Locates `warden-gui` the same way `warden-common::notify` locates this
/// helper: next to the currently running binary, falling back to `PATH`.
fn gui_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join("warden-gui")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("warden-gui"))
}

/// Scans `/proc` for an already-running process owned by this same uid
/// that has graphical-session environment variables set, and returns
/// whatever it finds. This helper's own process (spawned by the root
/// daemon, whose environment has none of this - it's a systemd service,
/// not a desktop session) never has `DISPLAY`/`WAYLAND_DISPLAY` set on
/// its own, unlike a process actually started *within* the target
/// user's desktop session. A standard technique for launching a GUI app
/// from outside a session context, needed here for the same underlying
/// reason `connect()` above hardcodes the D-Bus session bus path instead
/// of trusting an inherited `DBUS_SESSION_BUS_ADDRESS`. Without this,
/// `warden-gui` inherits none of it and GTK panics immediately trying to
/// connect to a display that, as far as its own environment says,
/// doesn't exist - confirmed live: the spawned process showed up as an
/// instant zombie, no window ever appeared, and the daemon's "launched
/// warden-gui" log line gave no hint anything was wrong.
fn session_environment() -> Vec<(String, String)> {
    const WANTED: &[&str] = &["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"];
    let my_uid = nix::unistd::getuid().as_raw();

    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if std::os::unix::fs::MetadataExt::uid(&meta) != my_uid {
            continue;
        }
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else { continue };
        let found: Vec<(String, String)> = environ
            .split(|&b| b == 0)
            .filter_map(|var| std::str::from_utf8(var).ok())
            .filter_map(|s| s.split_once('='))
            .filter(|(key, _)| WANTED.contains(key))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if found.iter().any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY") {
            return found;
        }
    }
    Vec::new()
}

/// Spawns the GUI jumped straight to this incident's detail view. This
/// helper is already running as the target desktop user (that's its
/// entire purpose - see `warden_common::notify`), so no privilege
/// juggling is needed here, unlike if the root daemon tried to do this
/// itself. Best-effort: a user who hasn't installed the GUI yet, or
/// whose desktop session can't launch it for some reason, must never
/// take this listener down over it.
fn launch_gui(incident_id: &str) {
    let mut command = std::process::Command::new(gui_path());
    command.arg("--incident").arg(incident_id);
    for (key, value) in session_environment() {
        command.env(key, value);
    }
    match command.spawn() {
        Ok(_) => info!(incident_id, "launched warden-gui for clicked notification"),
        Err(e) => warn!(incident_id, error = %e, "failed to launch warden-gui"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(run_listener(correlations.clone()));
    run_sender(correlations).await
}
