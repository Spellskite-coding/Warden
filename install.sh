#!/usr/bin/env bash
#
# Warden EDR installer.
#
# Builds Warden from the source tree this script lives in and installs it
# on THIS machine: binaries to /usr/local/bin, config to /etc/warden,
# state to /var/lib/warden, systemd units, and (best-effort) the desktop
# GUI + its icon. Meant to be run once per machine, and re-run to upgrade
# an existing install in place.
#
# This script itself runs privileged system operations (installing
# packages, compiling and installing binaries, writing systemd units).
# Read it before running it, the way you would any installer that asks
# for root.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/warden"
STATE_DIR="/var/lib/warden"
SYSTEMD_DIR="/etc/systemd/system"
SHARE_DIR="/usr/share/warden"

log()  { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m==> warning:\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m==> error:\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || die "must be run as root (it installs system packages, systemd units, and binaries owned by root)"

if [ ! -f /etc/os-release ]; then
    die "cannot identify the distro: /etc/os-release is missing"
fi
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_ID_LIKE="${ID_LIKE:-}"

log "detected distro: ${PRETTY_NAME:-$DISTRO_ID} (id=$DISTRO_ID)"

# ---------------------------------------------------------------------------
# Step 0: dependency check - fail fast, before touching the system at all,
# if a hard prerequisite the user has to supply themselves is missing.
# Nothing below this point runs (no apt/dnf/pacman, no writes anywhere)
# until this passes, so a missing dependency never leaves the system
# half-modified.
# ---------------------------------------------------------------------------

# rustup installs Rust per-user, not system-wide - so the common case is
# a regular user (often the one invoking `sudo ./install.sh`) already
# has cargo on THEIR OWN PATH, but root's PATH never sees it. But this
# script can equally be run from a genuine root login/session with no
# other account at all (e.g. a minimal Debian install nobody bothered
# creating a separate user on) - `$SUDO_USER` is only ever set when
# invoked *through* `sudo`, so that case looks just like "cargo is
# missing" here. INSTALL_FOR_USER picks the right account either way:
# the sudo-invoking user if there is one, otherwise root itself, since
# there's no one else to install it for.
INSTALL_FOR_USER="${SUDO_USER:-root}"
INSTALL_FOR_HOME="$(getent passwd "$INSTALL_FOR_USER" | cut -d: -f6)"

# Runs a command AS $INSTALL_FOR_USER, so anything it writes (a fresh
# rustup install, a `cargo binstall`-fetched binary under ~/.cargo/bin) is
# owned by that user, not by root - important since these land inside
# their home directory and they'll keep using that toolchain themselves
# outside of Warden. (root's own $HOME is pointed at $INSTALL_FOR_HOME
# too, further down, so a plain `cargo build` run directly as root still
# finds the right toolchain; this helper is specifically for steps whose
# *output* should belong to the target user.) PATH is set explicitly
# because a non-login, non-interactive `bash -c` never sources
# .bashrc/.profile (where rustup's installer normally adds its bin dir),
# so it wouldn't otherwise see rustup/cargo at all.
# $INSTALL_FOR_HOME (a passwd `home` field, via `getent`) is passed as an
# actual environment variable to the nested `bash -c`, not spliced into
# the command string itself: a review pointed out that splicing it in
# directly (`"PATH=\"$INSTALL_FOR_HOME/.cargo/bin:...\"; $1"`, evaluated
# as literal shell text by the nested bash) would let a `"`/`$(...)`/
# backtick in that field break out of the intended quoting and execute
# as root. Not reachable through a normal local `useradd`, but realistic
# for an LDAP/SSSD-backed account with a self-service `homeDirectory`
# attribute - and this script runs as root, so it's worth closing rather
# than trusting every possible NSS backend to sanitize that field.
# `VAR=value cmd` prefix-assignment (and `env VAR=value cmd`) both pass
# the value as one literal argv element with no re-parsing, unlike
# embedding it inside a string that a later `bash -c` interprets as code.
run_as_install_user() {
    # shellcheck disable=SC2016 # deliberately unexpanded here - $INSTALL_FOR_HOME/$PATH expand inside the nested bash -c, not this one
    local cmd='PATH="$INSTALL_FOR_HOME/.cargo/bin:$PATH"; '"$1"
    if [ "$INSTALL_FOR_USER" = "root" ]; then
        INSTALL_FOR_HOME="$INSTALL_FOR_HOME" bash -c "$cmd"
    else
        sudo -u "$INSTALL_FOR_USER" env "INSTALL_FOR_HOME=$INSTALL_FOR_HOME" bash -c "$cmd"
    fi
}

# Installs rustup for $INSTALL_FOR_USER and puts its bin dir on PATH for
# the rest of this script.
install_rustup_for() {
    log "installing rustup for $INSTALL_FOR_USER"
    run_as_install_user 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default'
}

# Checks root's own PATH first, then $INSTALL_FOR_USER's `~/.cargo/bin`
# (covers a rustup install that already exists but isn't on root's PATH)
# before concluding cargo is genuinely missing.
if ! command -v cargo >/dev/null 2>&1; then
    if [ -n "$INSTALL_FOR_HOME" ] && [ -x "$INSTALL_FOR_HOME/.cargo/bin/cargo" ]; then
        export PATH="$INSTALL_FOR_HOME/.cargo/bin:$PATH"
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo/rustc not found."
    if [ -t 0 ]; then
        read -r -p "Install rustup now for '$INSTALL_FOR_USER' to build Warden? [y/N] " reply
    else
        reply="n"
        warn "not running interactively - skipping the prompt."
    fi

    if [[ "$reply" =~ ^[Yy]$ ]]; then
        if install_rustup_for; then
            export PATH="$INSTALL_FOR_HOME/.cargo/bin:$PATH"
        else
            die "rustup installation failed. Install Rust yourself (https://rustup.rs) and re-run this script."
        fi
    else
        die "cargo/rustc required to build Warden from source. Install Rust (https://rustup.rs) for '$INSTALL_FOR_USER' and re-run this script. Nothing on this system has been changed yet."
    fi
fi
log "found cargo: $(cargo --version)"

# From here on, make root's own $HOME match the account cargo/rustup
# actually live under. Under `sudo ./install.sh` (the normal case) $HOME
# stays /root for this whole script even after PATH above was pointed at
# $INSTALL_FOR_USER's cargo bin dir - and a rustup-provided cargo/rustc,
# invoked directly as root with that hijacked PATH, still resolves
# toolchains and the registry under $HOME (i.e. /root), not under the
# target user's real ~/.rustup and ~/.cargo. Confirmed on a real box:
# without this, `cargo build`/`rustup toolchain install` here silently
# used or created a second, separate install under /root instead of the
# one actually set up for $INSTALL_FOR_USER. Harmless when cargo turned
# out to be the distro-packaged one instead (e.g. apt's) - that doesn't
# key off $HOME at all. This only affects root's own environment for the
# rest of this script (build steps still run as root; only their
# *toolchain lookup* changes) - the separate `run_as_install_user` helper
# below is for steps that should also be *owned* by the target user, like
# installing bpf-linker into their own ~/.cargo/bin.
export HOME="$INSTALL_FOR_HOME"

# ---------------------------------------------------------------------------
# Step 1: OS packages
#
# Only the apt (Debian/Ubuntu/Kali) path has actually been exercised
# end-to-end tonight, on a real Kali VM - the dnf/pacman branches follow
# the same package-name conventions documented for gtk4-devel/libadwaita
# in the RockyLinux build image (including CRB needing to be enabled
# there for libadwaita-devel/gobject-introspection-devel), but have not
# been run for real yet. Say so rather than implying equal confidence.
# ---------------------------------------------------------------------------

install_packages() {
    case "$DISTRO_ID" in
        debian | ubuntu | kali | linuxmint | pop)
            log "installing build dependencies via apt (validated path)"
            apt-get update -qq
            apt-get install -y --no-install-recommends \
                build-essential pkg-config curl git \
                libgtk-4-dev libadwaita-1-dev \
                clang llvm libelf-dev
            ;;
        fedora | rhel | rocky | almalinux | centos)
            warn "dnf path is untested end-to-end - please report back if this breaks"
            if command -v dnf5 >/dev/null 2>&1 || dnf --version >/dev/null 2>&1; then
                dnf install -y dnf-plugins-core
                dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null || true
            fi
            dnf install -y gcc pkgconf-pkg-config make curl git \
                gtk4-devel libadwaita-devel glib2-devel gobject-introspection-devel \
                pango-devel cairo-devel cairo-gobject-devel gdk-pixbuf2-devel graphene-devel \
                clang llvm elfutils-libelf-devel
            ;;
        arch | manjaro)
            warn "pacman path is untested end-to-end - please report back if this breaks"
            pacman -Sy --needed --noconfirm base-devel pkgconf curl git gtk4 libadwaita clang llvm libelf
            ;;
        opensuse* | sles)
            warn "zypper path is untested end-to-end - please report back if this breaks"
            zypper --non-interactive install gcc pkg-config curl git gtk4-devel libadwaita-devel clang llvm libelf-devel
            ;;
        *)
            if [[ "$DISTRO_ID_LIKE" == *debian* ]]; then
                warn "unrecognized distro id '$DISTRO_ID' but ID_LIKE contains debian - trying the apt path"
                apt-get update -qq
                apt-get install -y --no-install-recommends build-essential pkg-config curl git libgtk-4-dev libadwaita-1-dev clang llvm libelf-dev
            else
                die "unsupported distro '$DISTRO_ID' - install build-essential/gcc, pkg-config, gtk4-devel, libadwaita-devel, clang/llvm and libelf-devel manually, then re-run"
            fi
            ;;
    esac
}

install_packages

# ---------------------------------------------------------------------------
# Step 2: nightly Rust toolchain, for the eBPF modules only
# ---------------------------------------------------------------------------

# eBPF (exec/network modules) needs a nightly toolchain + bpf-linker + the
# nightly rust-src component, on top of the stable toolchain the rest of
# the workspace builds with. Best-effort: warn and skip those two modules
# rather than failing the whole install if this can't be set up.

# rustup can be installed for $INSTALL_FOR_USER even when Step 0 never
# needed to look in $INSTALL_FOR_HOME/.cargo/bin itself - e.g. the
# distro-packaged cargo (apt's `cargo`) satisfies Step 0's check directly
# on root's own PATH, so root's PATH is never extended there. Check for
# rustup under the target user's cargo bin dir explicitly here too, or
# this section would wrongly conclude rustup is missing and skip eBPF
# even when a working rustup + bpf-linker install already exists.
if ! command -v rustup >/dev/null 2>&1 && [ -x "$INSTALL_FOR_HOME/.cargo/bin/rustup" ]; then
    export PATH="$INSTALL_FOR_HOME/.cargo/bin:$PATH"
fi

EBPF_AVAILABLE=1
if ! command -v rustup >/dev/null 2>&1; then
    # A real, common case: `cargo`/`rustc` installed via the distro's own
    # package (e.g. `apt install cargo`) rather than rustup - satisfies
    # Step 0's check, but there is no toolchain manager to fetch a
    # nightly with, and distro-packaged rustc is stable-only.
    warn "rustup not found (cargo appears to be distro-packaged, not rustup-installed)."
    warn "Without it, warden-exec/warden-network (fileless-exec and network detection) cannot be built."

    if [ -t 0 ]; then
        read -r -p "Install rustup now for '$INSTALL_FOR_USER' to enable them? [y/N] " reply
    else
        reply="n"
        warn "not running interactively - skipping the prompt."
    fi

    if [[ "$reply" =~ ^[Yy]$ ]]; then
        if install_rustup_for; then
            export PATH="$INSTALL_FOR_HOME/.cargo/bin:$PATH"
            log "rustup installed: $(rustup --version | head -1)"
        else
            warn "rustup installation failed - skipping warden-exec/warden-network"
            EBPF_AVAILABLE=0
        fi
    else
        warn "skipping warden-exec/warden-network. To enable them later, install Rust via rustup (https://rustup.rs) and re-run this script."
        EBPF_AVAILABLE=0
    fi
fi
if [ "$EBPF_AVAILABLE" -eq 1 ] && ! run_as_install_user 'rustup toolchain list 2>/dev/null | grep -q nightly'; then
    warn "no nightly Rust toolchain found - attempting to install one for the eBPF modules (exec/network)"
    if ! run_as_install_user 'rustup toolchain install nightly --component rust-src'; then
        warn "installing the nightly toolchain failed - skipping warden-exec/warden-network"
        EBPF_AVAILABLE=0
    fi
fi
if [ "$EBPF_AVAILABLE" -eq 1 ] && ! command -v bpf-linker >/dev/null 2>&1; then
    log "installing bpf-linker for the eBPF modules"
    # bpf-linker links against libLLVM and must match the exact LLVM build
    # used by the Rust nightly toolchain - not any system-packaged LLVM.
    # Verified the hard way: on a real box, apt's llvm-21 AND llvm-19 both
    # fail `cargo install bpf-linker` identically ("undefined symbol:
    # LLVMParseIRInContext2"), proving it's not just "too new a version".
    # bpf-linker's own docs discourage `cargo install` for regular users
    # for exactly this reason and recommend a prebuilt binary instead, so
    # that's the primary path here: cargo-binstall fetches one already
    # linked against a matching LLVM, sidestepping the mismatch entirely.
    # It always resolves bpf-linker's latest release, which itself tracks
    # rustc nightly's LLVM on a rolling basis - so as long as both rustup's
    # nightly and bpf-linker stay on "latest" (as this script always
    # installs them), they stay compatible; pinning either one on its own
    # is what would break this. `cargo install` from source is kept as a
    # last-resort fallback only, for a box with no network access to
    # GitHub releases.
    if ! run_as_install_user 'command -v cargo-binstall >/dev/null 2>&1 || curl -L --proto "=https" --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash'; then
        warn "installing cargo-binstall failed"
    fi
    if run_as_install_user 'cargo binstall bpf-linker -y'; then
        :
    elif run_as_install_user 'cargo install bpf-linker'; then
        warn "installed bpf-linker by compiling from source (cargo-binstall unavailable) - this can fail if the system's LLVM doesn't match rustc nightly's exactly"
    else
        warn "installing bpf-linker failed - skipping warden-exec/warden-network"
        EBPF_AVAILABLE=0
    fi
fi
if [ "$EBPF_AVAILABLE" -eq 0 ]; then
    warn "eBPF toolchain unavailable - skipping warden-exec/warden-network (fileless-exec and network detection)."
    warn "Core protection (ransomware, persistence, privesc, yara) is unaffected."
fi

# ---------------------------------------------------------------------------
# Step 3: figure out the target desktop user
# ---------------------------------------------------------------------------

TARGET_USER="${WARDEN_TARGET_USER:-${SUDO_USER:-}}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    read -r -p "Desktop username Warden should protect and notify: " TARGET_USER
fi
id "$TARGET_USER" >/dev/null 2>&1 || die "no such user: $TARGET_USER"
log "target user: $TARGET_USER"

# ---------------------------------------------------------------------------
# Step 4: stop any existing install before touching its files
#
# Learned the hard way tonight: persistence watches /etc/systemd/system
# for new/changed unit files and /etc/cron.d, /etc/sudoers.d etc. for new
# entries, and will happily quarantine this script's own unit files or a
# config edit as "suspicious" if Warden is still running while this
# script writes them - it can't tell a legitimate upgrade from an
# attacker doing the exact same thing. Stopping first sidesteps this
# entirely, the same way installing a systemd unit before Warden's first
# start does.
# ---------------------------------------------------------------------------

if systemctl list-unit-files warden.service >/dev/null 2>&1; then
    log "stopping existing Warden services before upgrading"
    systemctl stop warden.service warden-exec.service warden-network.service 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 5: build
# ---------------------------------------------------------------------------

log "building the core workspace (warden, warden-common, detection modules, warden-notify-helper)"
( cd "$REPO_DIR" && cargo build --release --workspace )

GUI_BUILT=0
# A review pointed out that redirecting to a fixed, predictable /tmp path
# (as this used to) is a classic local root-file-clobber primitive: this
# script runs as root, /tmp is world-writable, and any local user could
# pre-create /tmp/warden-gui-build.log as a symlink to an arbitrary file
# before this runs - root would then open (and truncate) whatever that
# symlink points at. `mktemp` creates a fresh file itself (O_EXCL under
# the hood), so there's nothing for a pre-planted symlink to redirect.
WARDEN_GUI_BUILD_LOG="$(mktemp /tmp/warden-gui-build.XXXXXX.log)"
if cargo build --release -p warden-gui --manifest-path "$REPO_DIR/warden-gui/Cargo.toml" 2>"$WARDEN_GUI_BUILD_LOG"; then
    GUI_BUILT=1
else
    warn "warden-gui failed to build (see $WARDEN_GUI_BUILD_LOG) - continuing without the GUI"
fi

EBPF_BUILT=0
if [ "$EBPF_AVAILABLE" -eq 1 ]; then
    log "building the eBPF workspace (warden-exec, warden-network)"
    if ( cd "$REPO_DIR/ebpf-probe" && cargo build --release ); then
        EBPF_BUILT=1
    else
        warn "eBPF workspace failed to build - continuing without warden-exec/warden-network"
    fi
fi

# ---------------------------------------------------------------------------
# Step 6: install binaries
# ---------------------------------------------------------------------------

log "installing binaries to $BIN_DIR"
install -m 755 -o root -g root "$REPO_DIR/target/release/warden" "$BIN_DIR/warden"
install -m 755 -o root -g root "$REPO_DIR/target/release/warden-notify-helper" "$BIN_DIR/warden-notify-helper"

if [ "$GUI_BUILT" -eq 1 ]; then
    install -m 755 -o root -g root "$REPO_DIR/target/release/warden-gui" "$BIN_DIR/warden-gui"
fi
if [ "$EBPF_BUILT" -eq 1 ]; then
    install -m 755 -o root -g root "$REPO_DIR/ebpf-probe/target/release/warden-exec" "$BIN_DIR/warden-exec"
    install -m 755 -o root -g root "$REPO_DIR/ebpf-probe/target/release/warden-network" "$BIN_DIR/warden-network"
fi

# Warden's detection code embeds the very patterns it looks for as literal
# strings (e.g. "/dev/tcp/" for reverse-shell detection), which end up
# baked into the compiled binaries themselves - so Warden's own YARA
# content scanner can flag its own executables as suspicious. These are
# root-owned paths this script just built and installed, not something a
# regular user could plant something into, and each exception is a `File`
# exception - hash-pinned to what was JUST installed - so swapping one of
# these binaries out later invalidates the exception automatically. Runs
# on every (re)install, keeping the hash current. Deliberately narrow:
# only the binaries themselves, never the systemd units or config, so
# tampering with those still gets detected.
log "exempting Warden's own binaries from its own detection"
for bin in "$BIN_DIR/warden" "$BIN_DIR/warden-notify-helper" "$BIN_DIR/warden-gui" "$BIN_DIR/warden-exec" "$BIN_DIR/warden-network"; do
    [ -x "$bin" ] || continue
    "$BIN_DIR/warden" --add-exception "$bin" >/dev/null
done

# ---------------------------------------------------------------------------
# Step 7: config (never overwrite an existing one - this is an upgrade
# path too, and a re-run must not clobber a config someone has already
# tuned)
# ---------------------------------------------------------------------------

mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    log "writing default config to $CONFIG_DIR/config.toml (mode=enforce - protection is active immediately; switch to monitor from the GUI or here if you'd rather watch first)"
    cat > "$CONFIG_DIR/config.toml" <<EOF
# Warden EDR configuration.
#
# mode: "enforce" actually kills/quarantines/strips what it detects;
# "monitor" only logs/notifies what it would have done. Enforce is the
# default so protection is active as soon as this install finishes - flip
# to monitor here (or from the GUI's Dashboard, which also requires your
# root/admin password to change) if you'd rather watch it for a while on
# this machine first.
mode = "enforce"
target_user = "$TARGET_USER"
EOF
else
    log "existing config found at $CONFIG_DIR/config.toml, leaving it untouched"
fi

# ---------------------------------------------------------------------------
# Step 8: state directories
# ---------------------------------------------------------------------------

# $STATE_DIR itself, not just its quarantine/ leaf, needs an explicit
# chmod: mkdir -p creates any missing parent with the process's current
# umask (often 0022/0755), and only the leaf directory was hardened
# below - review found this left a narrow but real window where, on a
# freshly installed machine, /var/lib/warden was listable (filenames
# only - quarantine/, history.jsonl, honeypot_seed - never their
# content, which is separately protected at 0600/0700 each) by any local
# user until whichever of `warden`/`warden-exec`/`warden-network`
# happens to touch the path first at runtime re-hardens it themselves.
mkdir -p "$STATE_DIR/quarantine"
chmod 700 "$STATE_DIR"
chmod 700 "$STATE_DIR/quarantine"

# ---------------------------------------------------------------------------
# Step 9: systemd units
# ---------------------------------------------------------------------------

log "installing systemd units"
install -m 644 -o root -g root "$REPO_DIR/systemd/warden.service" "$SYSTEMD_DIR/warden.service"

# warden.service ships with ProtectSystem=strict (the whole filesystem
# read-only except /dev, /proc, /sys, and RuntimeDirectory=warden) - see
# that file's own comment for why. Everything else Warden actually
# writes to depends on the target user (their $HOME, whose exact locale-
# named subdirectories vary) and can't be hardcoded into a file this repo
# ships, so it's computed here, at install time, into a drop-in instead
# of editing the unit file directly - the same pattern this script
# already uses for config.toml (never overwritten on re-run, since a
# drop-in this script fully owns and regenerates every run is simpler and
# safer than trying to hand-merge into a file an admin might have
# customized).
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -n "$TARGET_HOME" ] || die "could not resolve a home directory for target user '$TARGET_USER'"
log "writing systemd sandboxing drop-in (ReadWritePaths for $TARGET_USER's home, scratch dirs, and the system dirs persistence/privesc can quarantine/strip)"
mkdir -p "$SYSTEMD_DIR/warden.service.d"
{
    echo "[Service]"
    # Each path prefixed with '-': systemd's "ignore if this path doesn't
    # exist" marker, since which of /etc/cron.d, /etc/sudoers.d, etc.
    # actually exist varies by distro (exactly the same reasoning
    # `warden-privesc::config::existing_only` already applies in Rust for
    # its own watch-dir list) - a missing one here must not stop the
    # service from starting at all.
    for path in \
        "$STATE_DIR" \
        "$TARGET_HOME" \
        /tmp /var/tmp /dev/shm \
        /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin \
        /etc/cron.d /etc/sudoers.d /etc/systemd/system /etc/xdg/autostart /etc/profile.d /var/spool/cron
    do
        echo "ReadWritePaths=-$path"
    done
} > "$SYSTEMD_DIR/warden.service.d/10-paths.conf"
chmod 644 "$SYSTEMD_DIR/warden.service.d/10-paths.conf"

UNITS="warden.service"
if [ "$EBPF_BUILT" -eq 1 ]; then
    install -m 644 -o root -g root "$REPO_DIR/systemd/warden-exec.service" "$SYSTEMD_DIR/warden-exec.service"
    install -m 644 -o root -g root "$REPO_DIR/systemd/warden-network.service" "$SYSTEMD_DIR/warden-network.service"
    UNITS="$UNITS warden-exec.service warden-network.service"
fi

systemctl daemon-reload
# shellcheck disable=SC2086  # $UNITS is a deliberately space-separated list of unit names
systemctl enable --now $UNITS
log "Warden services started: $UNITS"

# ---------------------------------------------------------------------------
# Step 10: GUI - icon, .desktop entry, branding asset
# ---------------------------------------------------------------------------

if [ "$GUI_BUILT" -eq 1 ]; then
    log "installing the GUI's icon and desktop entry"
    mkdir -p "$SHARE_DIR"
    install -m 644 -o root -g root "$REPO_DIR/branding/logo.png" "$SHARE_DIR/logo.png"

    for sz in 16 32 48 64 128 256; do
        icon_dir="/usr/share/icons/hicolor/${sz}x${sz}/apps"
        mkdir -p "$icon_dir"
        install -m 644 -o root -g root "$REPO_DIR/warden-gui/data/icons/warden-${sz}.png" "$icon_dir/warden.png"
    done
    mkdir -p /usr/share/icons/hicolor/scalable/apps
    install -m 644 -o root -g root "$REPO_DIR/warden-gui/data/icons/warden.svg" /usr/share/icons/hicolor/scalable/apps/warden.svg

    install -m 644 -o root -g root "$REPO_DIR/warden-gui/data/warden-gui.desktop" /usr/share/applications/warden-gui.desktop

    gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo
log "Warden installed."
# Read back the actual configured mode rather than assuming - it's
# "enforce" on a fresh install (as written above) but could be anything
# an existing config.toml already had, which this script never touches.
CURRENT_MODE="$(grep -E '^\s*mode\s*=' "$CONFIG_DIR/config.toml" 2>/dev/null | head -1 | sed -E 's/^\s*mode\s*=\s*"?([a-z]+)"?.*/\1/')"
echo "  Config:    $CONFIG_DIR/config.toml (mode=${CURRENT_MODE:-enforce})"
echo "  Services:  systemctl status $UNITS"
echo "  Logs:      journalctl -u warden.service -f"
if [ "$GUI_BUILT" -eq 1 ]; then
    echo "  GUI:       search for \"Warden\" in your application launcher, or run warden-gui"
else
    echo "  GUI:       not built - see $WARDEN_GUI_BUILD_LOG"
fi
if [ "$EBPF_BUILT" -eq 0 ]; then
    echo "  Note:      exec/network (eBPF) modules were not installed - core protection is still active"
fi
