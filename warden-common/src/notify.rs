use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use tracing::{debug, info, warn};
use zbus::zvariant::Value;
use zbus::{Connection, ConnectionBuilder, Proxy};

use crate::event::Severity;

/// How long a notification->incident correlation is kept around waiting
/// for a click. Generous on purpose (a notification itself can stay on
/// screen indefinitely at Critical urgency, see `expire_ms` below), but
/// still bounded so a long-running agent's memory doesn't grow forever
/// from notifications nobody ever clicks.
const CORRELATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Pops a desktop notification via the standard freedesktop D-Bus
/// Notifications service (GNOME Shell, dunst, mako, KDE Plasma, ...), and
/// listens for the user clicking it.
///
/// Warden runs as root, but the notification has to land on a logged-in
/// user's desktop session - not root's. The session message bus is
/// per-user and normally auto-discovered via the `DBUS_SESSION_BUS_ADDRESS`
/// / `XDG_RUNTIME_DIR` environment variables of the *calling process's own*
/// session, which for a root system service point at root's (nonexistent)
/// session, not the desktop user's. So instead of relying on that
/// discovery, this connects directly to the well-known per-user socket
/// path `/run/user/<uid>/bus`; root can open it regardless of its 0700
/// permissions since DAC checks don't apply to root.
pub struct Notifier {
    target_uid: u32,
    /// D-Bus notification id (returned by `Notify()`) -> the
    /// `DetectionEvent::id` it was raised for, plus when the entry was
    /// added (for TTL pruning). Shared with the background listener task
    /// so an `ActionInvoked` signal can be traced back to the incident
    /// that raised the notification the user clicked.
    correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>>,
}

impl Notifier {
    pub fn new(target_uid: u32) -> Self {
        let correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(listen_for_actions(target_uid, correlations.clone()));
        Self { target_uid, correlations }
    }

    /// Best-effort: a user who is not currently logged into a graphical
    /// session (bus socket doesn't exist yet, or no notification daemon is
    /// registered on it) must never take the agent down over this, so
    /// failures are only logged. `incident_id` should be a
    /// `DetectionEvent::id` - clicking the notification's "View details"
    /// action is correlated back to it (see `listen_for_actions`) so a
    /// future GUI can jump straight to that incident instead of just its
    /// home screen.
    pub async fn notify(&self, severity: Severity, summary: &str, body: &str, incident_id: &str) {
        match self.try_notify(severity, summary, body).await {
            Ok(notif_id) => {
                if let Ok(mut map) = self.correlations.lock() {
                    let now = Instant::now();
                    map.retain(|_, (_, added)| now.duration_since(*added) < CORRELATION_TTL);
                    map.insert(notif_id, (incident_id.to_string(), now));
                }
            }
            Err(e) => warn!(error = %e, uid = self.target_uid, "failed to show desktop notification (user not in a graphical session?)"),
        }
    }

    async fn try_notify(&self, severity: Severity, summary: &str, body: &str) -> Result<u32> {
        let address = format!("unix:path=/run/user/{}/bus", self.target_uid);
        let connection = ConnectionBuilder::address(address.as_str())?
            .build()
            .await
            .context("connecting to target user's session D-Bus")?;

        let urgency: u8 = match severity {
            Severity::Info | Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High | Severity::Critical => 2,
        };
        let expire_ms: i32 = if urgency == 2 { 0 } else { 10_000 };

        let mut hints: HashMap<&str, Value> = HashMap::new();
        hints.insert("urgency", Value::from(urgency));

        // "default" is the action most notification daemons (GNOME Shell,
        // KDE Plasma) invoke when the notification body itself is clicked,
        // not just a distinct action button - some daemons (dunst, mako)
        // only expose it as an actual button instead, which is why the
        // pair is still declared with a real, visible label rather than
        // left off.
        let actions = vec!["default", "View details"];

        let title = format!("Warden — {severity}: {summary}");
        let reply = connection
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &("Warden EDR", 0u32, "security-high-symbolic", title.as_str(), body, actions, hints, expire_ms),
            )
            .await
            .context("calling Notify over D-Bus")?;
        reply.body().deserialize().context("parsing Notify reply")
    }
}

/// Background task, one per `Notifier`: keeps a persistent connection to
/// the target user's session bus and listens for `ActionInvoked` (the
/// user clicked a notification Warden raised). Reconnects with a fixed
/// backoff on any failure - the target user may not be logged into a
/// graphical session yet when Warden starts, or their session may come
/// and go across logins, so a single connection attempt giving up forever
/// would silently stop reacting to clicks after the first failure.
async fn listen_for_actions(target_uid: u32, correlations: Arc<Mutex<HashMap<u32, (String, Instant)>>>) {
    loop {
        if let Err(e) = run_action_listener(target_uid, &correlations).await {
            debug!(error = %e, uid = target_uid, "notification action listener disconnected, retrying");
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

async fn run_action_listener(target_uid: u32, correlations: &Arc<Mutex<HashMap<u32, (String, Instant)>>>) -> Result<()> {
    let address = format!("unix:path=/run/user/{target_uid}/bus");
    let connection: Connection =
        ConnectionBuilder::address(address.as_str())?.build().await.context("connecting to target user's session D-Bus")?;

    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await
    .context("building Notifications proxy")?;

    let mut stream = proxy.receive_signal("ActionInvoked").await.context("subscribing to ActionInvoked")?;
    info!(uid = target_uid, "listening for desktop notification clicks");

    while let Some(msg) = stream.next().await {
        let Ok((notif_id, action_key)) = msg.body().deserialize::<(u32, String)>() else {
            continue;
        };

        let incident = correlations.lock().ok().and_then(|mut map| map.remove(&notif_id));
        let Some((incident_id, _)) = incident else {
            continue; // an action on a notification we didn't raise, or already expired
        };

        // TODO(GUI): once the warden-gui binary exists, launch it here,
        // e.g. `std::process::Command::new("warden-gui").arg("--incident").arg(&incident_id).spawn()`.
        // Logged for now so the correlation is visibly working end to end.
        info!(incident_id, action = action_key, "notification clicked - GUI integration pending, see PROGRESS.md");
    }

    Ok(())
}
