use tracing::{error, warn};
use warden_common::event::DetectionEvent;
use warden_common::history::HistoryStore;
use warden_common::notify::Notifier;
use warden_common::Severity;

/// Consumes `DetectionEvent`s from every detection module and fans them out
/// to the things every module needs regardless of what it detects: a log
/// line, a persisted history record, and a desktop notification. Response
/// (kill/quarantine) already happened inside the module before the event
/// reached this channel - see `warden_common::response`.
pub async fn run(mut rx: tokio::sync::mpsc::UnboundedReceiver<DetectionEvent>, notifier: Notifier, history: HistoryStore) {
    while let Some(evt) = rx.recv().await {
        match evt.severity {
            Severity::Critical | Severity::High => warn!(
                id = evt.id,
                module = evt.module,
                severity = %evt.severity,
                pid = evt.pid,
                action_taken = evt.action_taken,
                affected = evt.affected_paths.len(),
                "{}",
                evt.summary
            ),
            _ => tracing::info!(id = evt.id, module = evt.module, severity = %evt.severity, "{}", evt.summary),
        }

        if let Err(e) = history.record(&evt) {
            error!(id = evt.id, error = %e, "failed to persist detection event to history");
        }

        // Notify on anything Medium and above - Info/Low are for the log
        // and GUI history only, not worth interrupting the user.
        if evt.severity >= Severity::Medium {
            notifier.notify(evt.severity, &evt.summary, &evt.detail).await;
        }
    }
}
