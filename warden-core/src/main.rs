mod config;
mod control;
mod dispatcher;
mod scan;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};
use warden_common::control_protocol::{ModuleStatusEntry, StatusInfo};
use warden_common::history::HistoryStore;
use warden_common::notify::Notifier;
use warden_common::quarantine::Quarantine;

#[derive(Parser, Debug)]
#[command(name = "warden", version, about = "Autonomous endpoint detection & response for Linux workstations")]
struct Args {
    #[arg(short, long, default_value = "/etc/warden/config.toml")]
    config: PathBuf,

    #[arg(short, long)]
    verbose: bool,

    /// One-shot: hash `PATH` and add it (or replace its existing entry)
    /// in the shared exceptions list, then exit - does not start the
    /// daemon. Meant to be invoked via `pkexec` from the GUI, which is
    /// also why this is a real authenticated privilege escalation and
    /// not just reachable through the control socket: adding a standing
    /// exemption is a much stronger bypass than anything else the
    /// socket lets an already-connected (same-uid) client do.
    #[arg(long, value_name = "PATH")]
    add_exception: Option<PathBuf>,

    /// One-shot: remove `PATH`'s entry from the exceptions list, then
    /// exit. Same pkexec-only reasoning as --add-exception.
    #[arg(long, value_name = "PATH")]
    remove_exception: Option<PathBuf>,

    /// One-shot: restore a quarantined file (identified by its
    /// `ManifestEntry::quarantine_name`) back to its original location,
    /// reapplying its original mode/owner, then exit - does not start
    /// the daemon.
    ///
    /// Also adds an exception for the restored path: without one, a
    /// module would almost certainly re-detect and re-quarantine it
    /// within seconds of it landing back on disk (persistence re-flags
    /// a restored UnitDir file via inotify near-instantly, privesc
    /// within one 5s poll cycle) - "restore" that just bounces the file
    /// right back into quarantine isn't a real restore. That makes this
    /// exactly as powerful a bypass as --add-exception, hence the same
    /// pkexec-only reasoning: never reachable through the control
    /// socket, which is gated only on the connecting uid.
    #[arg(long, value_name = "ID")]
    restore_quarantine: Option<String>,

    /// One-shot: quarantine `PATH` right now (an operator reviewing a
    /// `yara-scan` or monitor-mode hit in the GUI and deciding to act on
    /// it), then exit.
    ///
    /// Originally reachable through the plain control socket on the
    /// (mistaken) reasoning that it only removes trust and so "can't
    /// grant a bypass" - a security review found that's false: with no
    /// path restriction and no exemption check, it let any process
    /// running as the target uid quarantine Warden's own systemd units,
    /// its config, or its own binaries (bypassing their exceptions
    /// entirely), which is a more powerful bypass than anything
    /// `--add-exception` guards against. Moved here, pkexec-only, same
    /// reasoning as every other action above. Also refuses to act on a
    /// path that currently has an exception: quarantining something you
    /// told Warden to trust is very likely a mistake, not something even
    /// an authenticated operator should be able to do silently - remove
    /// the exception first if that's really the intent.
    #[arg(long, value_name = "PATH")]
    quarantine_file: Option<PathBuf>,

    /// One-shot: switch the running mode ("monitor" or "enforce") in
    /// `config.toml`, then restart the daemon(s) so it actually takes
    /// effect, then exit. Rewrites just the `mode = "..."` line in place
    /// (or inserts one if the config left it at the default), leaving
    /// the rest of the file untouched, including any comments the
    /// operator added. Changing whether detections actually
    /// kill/quarantine anything is exactly the kind of consequential,
    /// deliberate action the rest of this file gates behind real
    /// `pkexec` authentication, so this is no different. The restart is
    /// deliberately bundled into this same authenticated action rather
    /// than left as a separate manual step: a config write with no
    /// visible effect until some later, disconnected restart is
    /// confusing UX, and this already has root; restarting
    /// warden.service/warden-exec.service/warden-network.service now
    /// costs nothing extra a user wouldn't already be granting.
    #[arg(long, value_name = "MODE")]
    set_mode: Option<String>,
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

    // Exception management: one-shot, no daemon, no config needed - the
    // GUI invokes these directly (list) or via pkexec (add/remove).
    if let Some(path) = &args.add_exception {
        let entry = warden_common::exceptions::add(path)?;
        match &entry {
            warden_common::exceptions::Exception::File { path, sha256 } => println!("Added exception: {path} (sha256 {sha256})"),
            warden_common::exceptions::Exception::Directory { path } => println!("Added exception: {path} (directory - no integrity check on its contents)"),
        }
        return Ok(());
    }
    if let Some(path) = &args.remove_exception {
        warden_common::exceptions::remove(path)?;
        println!("Removed exception for {}", path.display());
        return Ok(());
    }
    if let Some(quarantine_name) = &args.restore_quarantine {
        let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine"))?;
        let restored_path = quarantine.restore(quarantine_name)?;
        let exception = warden_common::exceptions::add(&restored_path)?;
        println!("Restored {} and added an exception for it", exception.path());
        return Ok(());
    }
    if let Some(path) = &args.quarantine_file {
        if warden_common::exceptions::is_exempt(path) {
            anyhow::bail!("{} has an active exception - remove it first if you really want to quarantine this file", path.display());
        }
        let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine"))?;
        match quarantine.take(path, "manual", -1, "quarantined manually by an operator via pkexec") {
            Ok(Some(dest)) => {
                println!("Quarantined {} to {}", path.display(), dest.display());
                let history = HistoryStore::new(std::path::Path::new("/var/lib/warden/history.jsonl"))?;
                let evt = warden_common::event::DetectionEvent::new(
                    "manual",
                    warden_common::event::Severity::High,
                    format!("manually quarantined: {}", path.display()),
                    format!("moved to {}", dest.display()),
                )
                .with_response(None, vec![dest], true);
                let _ = history.record(&evt);
            }
            Ok(None) => println!("{} is already gone - nothing to quarantine", path.display()),
            Err(e) => return Err(e),
        }
        return Ok(());
    }
    if let Some(mode) = &args.set_mode {
        let mode = mode.trim().to_lowercase();
        if mode != "monitor" && mode != "enforce" {
            anyhow::bail!("mode must be \"monitor\" or \"enforce\", got {mode:?}");
        }
        let path = &args.config;
        let data = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let new_line = format!("mode = \"{mode}\"");
        let mode_line_re = "mode";
        let mut found = false;
        let mut out_lines: Vec<String> = Vec::new();
        for line in data.lines() {
            let trimmed = line.trim_start();
            if !found && (trimmed.starts_with(mode_line_re) && trimmed[mode_line_re.len()..].trim_start().starts_with('=')) {
                out_lines.push(new_line.clone());
                found = true;
            } else {
                out_lines.push(line.to_string());
            }
        }
        if !found {
            out_lines.insert(0, new_line);
        }
        let mut new_data = out_lines.join("\n");
        new_data.push('\n');
        std::fs::write(path, new_data).with_context(|| format!("writing {}", path.display()))?;

        // Restart right away rather than leaving it for a separate,
        // later "Restart protection" click: this handler already got
        // one deliberate `pkexec` authentication for a consequential
        // action, and a mode switch that doesn't actually take effect
        // until some later, disconnected step is a confusing UX ("I
        // clicked Enforce, why does the Dashboard still say Monitor?").
        // Best-effort: `warden-exec`/`warden-network` may not be
        // installed on this machine (no eBPF toolchain at install time),
        // so their unit failing to restart shouldn't fail this whole
        // command - the config write already succeeded either way.
        let restart = std::process::Command::new("systemctl")
            .args(["restart", "warden.service", "warden-exec.service", "warden-network.service"])
            .status();
        match restart {
            Ok(status) if status.success() => println!("Set mode to {mode} in {} and restarted protection", path.display()),
            Ok(status) => println!("Set mode to {mode} in {} - restart returned {status}, check `systemctl status warden.service`", path.display()),
            Err(e) => println!("Set mode to {mode} in {} - could not run systemctl to restart: {e}", path.display()),
        }
        return Ok(());
    }

    init_tracing(args.verbose);

    let cfg = config::Config::load(&args.config)?;
    let target = cfg.resolve_target_user()?;
    info!(mode = ?cfg.mode, target_user = %cfg.target_user, home = %target.home.display(), "loaded config");

    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let notifier = Notifier::new(target.uid, target.gid);
    let history = HistoryStore::new(std::path::Path::new("/var/lib/warden/history.jsonl"))?;
    let quarantine = Quarantine::new(std::path::Path::new("/var/lib/warden/quarantine"))?;
    let dispatcher = tokio::spawn(dispatcher::run(event_rx, notifier, history.clone()));

    let mode = cfg.mode;
    let home = target.home.clone();

    let mut modules: tokio::task::JoinSet<(&'static str, Result<()>)> = tokio::task::JoinSet::new();

    let ransomware_cfg = cfg.ransomware.clone();
    let ransomware_home = home.clone();
    let ransomware_tx = event_tx.clone();
    let (target_uid, target_gid) = (target.uid, target.gid);
    let ransomware_ready = spawn_module(&mut modules, "ransomware", move |ready_tx| {
        warden_ransomware::run(ransomware_cfg, &ransomware_home, mode, target_uid, target_gid, ransomware_tx, ready_tx)
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

    let yara_cfg = cfg.yara.clone();
    let yara_home = home.clone();
    let yara_tx = event_tx.clone();
    let yara_ready = spawn_module(&mut modules, "yara", move |ready_tx| warden_yara::run(yara_cfg, &yara_home, mode, yara_tx, ready_tx));

    // Only tell systemd (and Restart=on-failure) we're up once at least one
    // module actually initialized - not just once its thread was spawned.
    // If every module fails to init, the host is silently unprotected, so
    // that case is fatal rather than reporting READY=1 anyway. A single
    // module failing while others come up is treated as degraded-but-
    // running, logged loudly above by wait_ready, rather than fatal - e.g.
    // a workstation with no /etc/cron.d yet shouldn't lose ransomware
    // protection over it.
    let (ransomware_ok, persistence_ok, privesc_ok, yara_ok) = tokio::join!(
        wait_ready("ransomware", ransomware_ready),
        wait_ready("persistence", persistence_ready),
        wait_ready("privesc", privesc_ready),
        wait_ready("yara", yara_ready),
    );

    if !ransomware_ok && !persistence_ok && !privesc_ok && !yara_ok {
        dispatcher.abort();
        modules.abort_all();
        anyhow::bail!("every detection module failed to initialize, refusing to report ready");
    }

    let status = StatusInfo {
        mode: format!("{mode:?}").to_lowercase(),
        target_user: cfg.target_user.clone(),
        modules: vec![
            ModuleStatusEntry { name: "ransomware".to_string(), ready: ransomware_ok },
            ModuleStatusEntry { name: "persistence".to_string(), ready: persistence_ok },
            ModuleStatusEntry { name: "privesc".to_string(), ready: privesc_ok },
            ModuleStatusEntry { name: "yara".to_string(), ready: yara_ok },
        ],
    };
    // Best-effort, like the notifier: a failure to bind this socket (e.g.
    // /run not writable in some unusual sandboxed test environment) must
    // never take detection down with it.
    let control_history = history.clone();
    let control_quarantine = quarantine.clone();
    let control_custom_rules_dir = cfg.yara.custom_rules_dir.clone();
    let control_target_home = target.home.clone();
    tokio::spawn(async move {
        if let Err(e) =
            control::run(control_history, control_quarantine, status, control_custom_rules_dir, target.uid, target.gid, control_target_home).await
        {
            error!(error = %e, "control socket failed");
        }
    });

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

