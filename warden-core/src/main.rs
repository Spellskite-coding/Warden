mod config;
mod dispatcher;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use warden_common::notify::Notifier;

#[derive(Parser, Debug)]
#[command(name = "warden", version, about = "Autonomous endpoint detection & response for Linux workstations")]
struct Args {
    #[arg(short, long, default_value = "/etc/warden/config.toml")]
    config: PathBuf,

    #[arg(short, long)]
    verbose: bool,
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)))
        .init();
}

/// Awaits one module's readiness signal and logs the outcome. Returns
/// whether the module is actually up and monitoring - not just whether its
/// thread was spawned.
async fn wait_ready(module: &'static str, ready_rx: tokio::sync::oneshot::Receiver<std::result::Result<(), String>>) -> bool {
    match ready_rx.await {
        Ok(Ok(())) => {
            info!(module, "module ready");
            true
        }
        Ok(Err(e)) => {
            error!(module, error = %e, "module failed to initialize");
            false
        }
        Err(_) => {
            error!(module, "module ended before reporting readiness (likely panicked)");
            false
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);

    let cfg = config::Config::load(&args.config)?;
    let target = cfg.resolve_target_user()?;
    info!(mode = ?cfg.mode, target_user = %cfg.target_user, home = %target.home.display(), "loaded config");

    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let notifier = Notifier::new(target.uid);
    let dispatcher = tokio::spawn(dispatcher::run(event_rx, notifier));

    let mode = cfg.mode;

    let (ransomware_ready_tx, ransomware_ready_rx) = tokio::sync::oneshot::channel();
    let ransomware_cfg = cfg.ransomware.clone();
    let ransomware_home = target.home.clone();
    let ransomware_event_tx = event_tx.clone();
    let mut ransomware = tokio::task::spawn_blocking(move || {
        warden_ransomware::run(ransomware_cfg, &ransomware_home, mode, ransomware_event_tx, ransomware_ready_tx)
    });

    let (persistence_ready_tx, persistence_ready_rx) = tokio::sync::oneshot::channel();
    let persistence_home = target.home.clone();
    let persistence_user = cfg.target_user.clone();
    let persistence_event_tx = event_tx.clone();
    let mut persistence = tokio::task::spawn_blocking(move || {
        warden_persistence::run(persistence_home, persistence_user, mode, persistence_event_tx, persistence_ready_tx)
    });

    // Only tell systemd (and Restart=on-failure) we're up once at least one
    // module actually initialized - not just once its thread was spawned.
    // If every module fails to init, the host is silently unprotected, so
    // that case is fatal rather than reporting READY=1 anyway. A single
    // module failing while another comes up is treated as degraded-but-
    // running, logged loudly above by wait_ready, rather than fatal - e.g.
    // a workstation with no /etc/cron.d yet shouldn't lose ransomware
    // protection over it.
    let (ransomware_ok, persistence_ok) = tokio::join!(wait_ready("ransomware", ransomware_ready_rx), wait_ready("persistence", persistence_ready_rx));

    if !ransomware_ok && !persistence_ok {
        dispatcher.abort();
        anyhow::bail!("every detection module failed to initialize, refusing to report ready");
    }
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    info!("warden ready");

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // If either module's loop ends (its own internal fatal error, not just
    // an init failure already handled above), treat it as fatal for the
    // whole process rather than trying to keep running half-blind: exit
    // non-zero so systemd's Restart=on-failure gives every module a clean
    // full re-init, instead of building a more complex per-module
    // supervisor that can restart just the failed one (a reasonable future
    // improvement, not done yet - see PROGRESS.md).
    tokio::select! {
        res = &mut ransomware => {
            dispatcher.abort();
            persistence.abort();
            return match res {
                Ok(Ok(())) => { info!("ransomware module loop exited"); Ok(()) }
                Ok(Err(e)) => { error!(error = %e, "ransomware module failed"); Err(e) }
                Err(e) => { error!(error = %e, "ransomware module task panicked"); Err(anyhow::anyhow!(e)) }
            };
        }
        res = &mut persistence => {
            dispatcher.abort();
            ransomware.abort();
            return match res {
                Ok(Ok(())) => { info!("persistence module loop exited"); Ok(()) }
                Ok(Err(e)) => { error!(error = %e, "persistence module failed"); Err(e) }
                Err(e) => { error!(error = %e, "persistence module task panicked"); Err(anyhow::anyhow!(e)) }
            };
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
            // Both modules' threads are parked in blocking kernel read()
            // syscalls with no way to interrupt them cleanly; dropping the
            // tokio runtime at the end of main() would wait for those
            // spawn_blocking tasks forever. There is no in-flight work
            // worth draining, so exit immediately.
            std::process::exit(0);
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
            std::process::exit(0);
        }
    }
}
