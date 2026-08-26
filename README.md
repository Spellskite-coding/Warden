# Warden

Autonomous endpoint detection & response (EDR) for Linux workstations,
written in Rust. No server, no cloud dependency, no agent-to-collector
traffic — everything runs locally as a single hardened systemd service,
with an optional desktop GUI.

Warden watches for the handful of things that actually matter on a single
workstation — ransomware, persistence mechanisms, privilege escalation,
and known-malicious file content — and either logs what it sees
(`monitor` mode) or kills/quarantines it immediately (`enforce` mode).

See [PROGRESS.md](PROGRESS.md) for the full development history,
every design decision and the reasoning behind it, and everything that's
been tested (including live red-team findings and their fixes).

## What it detects

- **Ransomware** (`warden-ransomware`): fanotify-based monitoring of the
  user's data directories. Flags a burst of high-entropy file rewrites
  (tracked per-process, per-directory, and globally, so fork-per-file and
  multi-directory spreading can't slip under any single counter),
  container-format signature forgery, and touches to seeded, per-machine
  randomized honeypot files planted among real user directories.
- **Persistence** (`warden-persistence`): inotify-based monitoring of
  cron, sudoers.d, systemd units, XDG autostart entries, profile.d, and
  shell rc files for new or modified entries, with heuristics for
  obviously suspicious content (reverse-shell one-liners, curl-pipe-shell,
  etc.) and diffing against a baseline to catch subtle appended lines.
- **Privilege escalation** (`warden-privesc`): polls for new setuid/setgid
  binaries and unexpected files dropped in system binary directories.
- **Malware signatures** (`warden-yara`): YARA-based scanning, both live
  (fanotify, on file close) and on-demand (`StartScan` over the control
  socket, restricted to the caller's own home directory and `/tmp`).
- **Fileless exec & network** (`ebpf-probe/`, optional): eBPF tracepoints
  on `sched_process_exec` and `inet_sock_set_state` for exec/network
  visibility beyond what filesystem watching alone can see. Needs a
  nightly Rust toolchain + `bpf-linker`; the rest of Warden works fully
  without it.

Every detection module runs its own independent watch loop inside the
same `warden` daemon process (except the two eBPF modules, which are
separate binaries/services). A single confirmed detection can kill the
offending process (`pidfd`-based, immune to PID-reuse races, with a
best-effort raw-`kill` fallback) and quarantine the affected files.

## Architecture at a glance

- **`warden`** (in `warden-core/`) — the main daemon. Runs as root
  (fanotify filesystem-wide marks, killing/quarantining arbitrary user
  processes, and stripping setuid bits all genuinely need it), but with a
  narrowed `CapabilityBoundingSet` and full systemd sandboxing
  (`ProtectSystem=strict`, `NoNewPrivileges`, `RestrictSUIDSGID`, ...) —
  see [systemd/warden.service](systemd/warden.service) for the exact
  directives and the reasoning behind each one.
- **`warden-common`** — shared building blocks: quarantine (with
  cross-process `flock`-protected manifest, setuid-stripping on copy),
  detection history, the exceptions list, XDG directory resolution,
  package-manager detection (to avoid flagging a legitimate `apt`/`dnf`
  upgrade), and `pidfd`-based process termination.
- **`warden-notify-helper`** — a tiny helper the daemon spawns with
  privileges dropped to the logged-in user, since a root process can't
  reach that user's D-Bus session bus. Talks to the daemon over
  stdin/stdout as newline-delimited JSON.
- **`warden-gui`** (GTK4 + libadwaita) — the desktop dashboard: live
  module status, detection history, quarantine management, on-demand
  scans, exception management, and mode switching — all consequential
  actions (`--add-exception`, `--quarantine-file`, `--set-mode`, ...) are
  gated behind real `pkexec` authentication, never reachable through the
  plain control socket.
- **Control socket** (`/run/warden/control.sock`) — a Unix domain socket,
  owner-only (`0600`, created under a restrictive `umask` so it's never
  briefly wider), for read-only GUI queries (status, history, on-demand
  scan) that don't need a privileged prompt.

## Building

Never built or run directly on a development host in this project's own
workflow — see [PROGRESS.md](PROGRESS.md)'s workflow rule. Build inside
the dedicated container:

```sh
docker build -t warden-build:rockylinux -f docker/Dockerfile.build .
docker run --rm -v "$PWD:/build" \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -w /build warden-build:rockylinux cargo build --release --workspace
```

The eBPF modules (`warden-exec`, `warden-network`) need a separate
nightly toolchain + `bpf-linker`, built via `docker/Dockerfile.build-ebpf`
against the `ebpf-probe/` sub-workspace.

Run the test suite and lints the same way:

```sh
docker run --rm -v "$PWD:/build" \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -w /build warden-build:rockylinux bash -c \
  "cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings"
```

[`.github/workflows/test.yml`](.github/workflows/test.yml) runs the same
build/test/clippy/`cargo-audit` checks automatically on every push and
pull request (not inside the Docker build container there, but on a
plain `ubuntu-latest` runner with the GTK4/libadwaita dev packages
installed directly).

## Installing (on a real machine)

```sh
sudo ./install.sh
```

Detects your distro's package manager (apt, dnf, pacman, or zypper),
installs build dependencies, builds Warden from source, installs the
systemd units (with a computed sandboxing drop-in for the target user's
actual home directory), and starts protection in either `enforce` mode
(kills/quarantines immediately) or `monitor` mode (logs only) — asked
interactively on a fresh install (defaults to `enforce` if not run
interactively; set `WARDEN_INSTALL_MODE=monitor` to skip the prompt).
Either way it's switchable anytime afterward from the GUI or
`warden --set-mode`. Safe to re-run to upgrade an existing install in
place — it never overwrites an existing `config.toml`, so re-running
never resets a mode you already chose.

To remove it:

```sh
sudo ./uninstall.sh            # stops services, removes binaries/units/GUI assets
                                # — config and quarantine are left in place
sudo ./uninstall.sh --purge    # also removes config and quarantine, after confirmation
```

Both scripts have been validated end-to-end (real install → real
detection → real uninstall) across every supported package-manager
family: apt on two real VMs (Debian 13, Ubuntu 25.10), and dnf/pacman/
zypper each in a dedicated systemd-as-PID1 Docker test image (see
`docker/Dockerfile.test.*`).

## Status

Under active development, hardened through multiple rounds of live
red-team testing against the running detection modules (fanotify TOCTOU
windows, package-manager spoofing, honeypot naming, burst-detector
bypasses, control-socket oracles, and more — every one confirmed live
and fixed; see PROGRESS.md for the full list). All four core detection
modules, the GUI, desktop notifications, the control socket, quarantine
with cross-process locking, and the installer/uninstaller are implemented
and tested. Not yet done: a simplified Sigma-rule detection layer,
`setcap`-based capability tracking for privesc (SUID/SGID only today),
and `cargo-deny` alongside the `cargo-audit` check already in place.

## License

MIT.
