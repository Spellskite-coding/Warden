use tracing::{info, warn};
use warden_common::event::DetectionEvent;
use warden_common::notify::Notifier;
use warden_common::Severity;

/// Consumes `DetectionEvent`s from every detection module and fans them out
/// to the things every module needs regardless of what it detects: a log
/// line and a desktop notification. Response (kill/quarantine) already
/// happened inside the module before the event reached this channel - see
/// `warden_common::response`.
pub async fn run(mut rx: tokio::sync::mpsc::UnboundedReceiver<DetectionEvent>, notifier: Notifier) {
    while let Some(evt) = rx.recv().await {
        match evt.severity {
            Severity::Critical | Severity::High => warn!(
                module = evt.module,
                severity = %evt.severity,
                pid = evt.pid,
                action_taken = evt.action_taken,
                affected = evt.affected_paths.len(),
                "{}",
                evt.summary
            ),
            _ => info!(module = evt.module, severity = %evt.severity, "{}", evt.summary),
        }

        // Notify on anything Medium and above - Info/Low are for the log
        // and future GUI history only, not worth interrupting the user.
        if evt.severity >= Severity::Medium {
            notifier.notify(evt.severity, &evt.summary, &evt.detail).await;
        }
    }
}
