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

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let ransomware_cfg = cfg.ransomware.clone();
    let mode = cfg.mode;
    let home = target.home.clone();
    let ransomware_event_tx = event_tx.clone();
    let ransomware =
        tokio::task::spawn_blocking(move || warden_ransomware::run(ransomware_cfg, &home, mode, ransomware_event_tx, ready_tx));

    // Only tell systemd (and Restart=on-failure) we're up once monitoring
    // actually initialized, not just once the worker thread was spawned -
    // otherwise a fanotify_init/mark failure would still report READY=1
    // and the host would be silently unprotected until the next restart.
    match ready_rx.await {
        Ok(Ok(())) => {
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
            info!("warden ready");
        }
        Ok(Err(e)) => {
            error!(error = %e, "ransomware module failed to initialize, not reporting ready");
        }
        Err(_) => {
            error!("ransomware module ended before reporting readiness (likely panicked)");
        }
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        res = ransomware => {
            dispatcher.abort();
            return match res {
                Ok(Ok(())) => { info!("ransomware module loop exited"); Ok(()) }
                Ok(Err(e)) => { error!(error = %e, "ransomware module failed"); Err(e) }
                Err(e) => { error!(error = %e, "ransomware module task panicked"); Err(anyhow::anyhow!(e)) }
            };
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
            // The ransomware module's thread is parked in a blocking
            // fanotify read() syscall with no way to interrupt it cleanly;
            // dropping the tokio runtime at the end of main() would wait
            // for that spawn_blocking task forever. There is no in-flight
            // work worth draining, so exit immediately.
            std::process::exit(0);
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
            std::process::exit(0);
        }
    }
}
