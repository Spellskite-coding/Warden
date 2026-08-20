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

/// Spawns one detection module on its own blocking thread (each module's
/// `run` blocks on a kernel read loop) and returns the oneshot receiver
/// the caller awaits for readiness. Threading the module name through the
/// task's own return value (rather than a side table) is what lets
/// `JoinSet::join_next` in `main` identify which module just ended without
/// a separate bookkeeping structure to keep in sync.
fn spawn_module<F>(modules: &mut tokio::task::JoinSet<(&'static str, Result<()>)>, name: &'static str, run: F) -> tokio::sync::oneshot::Receiver<std::result::Result<(), String>>
where
    F: FnOnce(tokio::sync::oneshot::Sender<std::result::Result<(), String>>) -> Result<()> + Send + 'static,
{
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    modules.spawn_blocking(move || (name, run(ready_tx)));
    ready_rx
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
    let home = target.home.clone();

    let mut modules: tokio::task::JoinSet<(&'static str, Result<()>)> = tokio::task::JoinSet::new();

    let ransomware_cfg = cfg.ransomware.clone();
    let ransomware_home = home.clone();
    let ransomware_tx = event_tx.clone();
    let ransomware_ready = spawn_module(&mut modules, "ransomware", move |ready_tx| {
        warden_ransomware::run(ransomware_cfg, &ransomware_home, mode, ransomware_tx, ready_tx)
    });

    let persistence_home = home.clone();
    let persistence_user = cfg.target_user.clone();
    let persistence_tx = event_tx.clone();
    let persistence_ready = spawn_module(&mut modules, "persistence", move |ready_tx| {
        warden_persistence::run(persistence_home, persistence_user, mode, persistence_tx, ready_tx)
    });

    let privesc_cfg = cfg.privesc.clone();
    let privesc_home = home.clone();
    let privesc_tx = event_tx.clone();
    let privesc_ready = spawn_module(&mut modules, "privesc", move |ready_tx| {
        warden_privesc::run(privesc_cfg, &privesc_home, mode, privesc_tx, ready_tx)
    });

    // Only tell systemd (and Restart=on-failure) we're up once at least one
    // module actually initialized - not just once its thread was spawned.
    // If every module fails to init, the host is silently unprotected, so
    // that case is fatal rather than reporting READY=1 anyway. A single
    // module failing while others come up is treated as degraded-but-
    // running, logged loudly above by wait_ready, rather than fatal - e.g.
    // a workstation with no /etc/cron.d yet shouldn't lose ransomware
    // protection over it.
    let (ransomware_ok, persistence_ok, privesc_ok) = tokio::join!(
        wait_ready("ransomware", ransomware_ready),
        wait_ready("persistence", persistence_ready),
        wait_ready("privesc", privesc_ready),
    );

    if !ransomware_ok && !persistence_ok && !privesc_ok {
        dispatcher.abort();
        modules.abort_all();
        anyhow::bail!("every detection module failed to initialize, refusing to report ready");
    }
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    info!("warden ready");

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // If any module's loop ends (its own internal fatal error, not just an
    // init failure already handled above), treat it as fatal for the whole
    // process rather than trying to keep running half-blind: exit non-zero
    // so systemd's Restart=on-failure gives every module a clean full
    // re-init, instead of building a more complex per-module supervisor
    // that can restart just the failed one (a reasonable future
    // improvement, not done yet - see PROGRESS.md).
    tokio::select! {
        joined = modules.join_next() => {
            dispatcher.abort();
            modules.abort_all();
            return match joined {
                Some(Ok((name, Ok(())))) => { info!(module = name, "module loop exited"); Ok(()) }
                Some(Ok((name, Err(e)))) => { error!(module = name, error = %e, "module failed"); Err(e) }
                Some(Err(e)) => { error!(error = %e, "module task panicked"); Err(anyhow::anyhow!(e)) }
                None => { error!("all modules already ended"); anyhow::bail!("no modules left running") }
            };
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
            // Every module's thread is parked in a blocking kernel read()
            // syscall with no way to interrupt it cleanly; dropping the
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

