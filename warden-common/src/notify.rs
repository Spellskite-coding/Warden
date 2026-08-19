use std::collections::HashMap;

use anyhow::{Context, Result};
use tracing::warn;
use zbus::zvariant::Value;
use zbus::ConnectionBuilder;

use crate::event::Severity;

/// Pops a desktop notification via the standard freedesktop D-Bus
/// Notifications service (GNOME Shell, dunst, mako, KDE Plasma, ...).
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
}

impl Notifier {
    pub fn new(target_uid: u32) -> Self {
        Self { target_uid }
    }

    /// Best-effort: a user who is not currently logged into a graphical
    /// session (bus socket doesn't exist yet, or no notification daemon is
    /// registered on it) must never take the agent down over this, so
    /// failures are only logged.
    pub async fn notify(&self, severity: Severity, summary: &str, body: &str) {
        if let Err(e) = self.try_notify(severity, summary, body).await {
            warn!(error = %e, uid = self.target_uid, "failed to show desktop notification (user not in a graphical session?)");
        }
    }

    async fn try_notify(&self, severity: Severity, summary: &str, body: &str) -> Result<()> {
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

        let title = format!("Warden — {severity}: {summary}");
        let reply = connection
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &("Warden EDR", 0u32, "security-high-symbolic", title.as_str(), body, Vec::<&str>::new(), hints, expire_ms),
            )
            .await
            .context("calling Notify over D-Bus")?;
        let _: u32 = reply.body().deserialize().context("parsing Notify reply")?;
        Ok(())
    }
}
