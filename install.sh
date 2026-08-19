#!/usr/bin/env bash
# Warden installer: builds the agent from this checkout, installs the
# binary, config, and systemd service, then starts and verifies it.
#
# Usage:
#   sudo ./install.sh                    # protects the user who ran sudo, monitor mode
#   sudo ./install.sh --user alice       # protects alice's $HOME explicitly
#   sudo ./install.sh --enforce          # starts directly in enforce mode (see warning below)
#
# Safe to re-run: rebuilds and reinstalls the binary and systemd unit, but
# never touches an existing /etc/warden/config.toml (so re-running to
# upgrade doesn't clobber settings you've already tuned).
set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi
log_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$1"; }
log_ok()   { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
log_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }
die() { log_err "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BIN_DEST=/usr/local/bin/warden
CONFIG_DIR=/etc/warden
CONFIG_FILE="$CONFIG_DIR/config.toml"
UNIT_SRC="$SCRIPT_DIR/systemd/warden.service"
UNIT_DEST=/etc/systemd/system/warden.service
UNIT_DROPIN_DIR=/etc/systemd/system/warden.service.d
QUARANTINE_DIR=/var/lib/warden/quarantine
SERVICE_NAME=warden

MODE="monitor"
TARGET_USER=""

usage() {
    cat <<EOF
Usage: sudo $0 [--enforce] [--user USERNAME]

  --user USERNAME  The desktop user Warden protects (\$HOME watched, desktop
                    session notified). Defaults to \$SUDO_USER (the user who
                    ran sudo), since that's who's running this installer on
                    their own workstation in the common case.
  --enforce         Start in Enforce mode (kill + quarantine) instead of the
                    default Monitor mode (log + notify only). Only pass this
                    once you've reviewed monitor-mode activity for a while
                    and are confident in the thresholds - see the README.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --enforce) MODE="enforce"; shift ;;
        --user) [ "$#" -ge 2 ] || die "--user requires a value"; TARGET_USER="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight checks - fail fast and clearly, this runs as root
# ---------------------------------------------------------------------------
log_info "Warden installer starting - preflight checks"

[ "$(id -u)" -eq 0 ] || die "must be run as root (try: sudo $0 $*)"

[ "$(uname -s)" = "Linux" ] || die "Warden only runs on Linux (uses fanotify, a Linux-only kernel API)"

command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl not found - this installer only supports systemd-managed hosts"
[ -d /run/systemd/system ] || die "systemd does not appear to be the running init system (no /run/systemd/system) - refusing to install a systemd service"

[ -f "$SCRIPT_DIR/Cargo.toml" ] && [ -f "$SCRIPT_DIR/warden-core/src/main.rs" ] || \
    die "run this script from inside a Warden checkout (Cargo.toml/warden-core/src/main.rs not found next to it)"

if [ -z "$TARGET_USER" ]; then
    TARGET_USER="${SUDO_USER:-}"
fi
[ -n "$TARGET_USER" ] || die "could not determine which user to protect - run via 'sudo' as that user, or pass --user USERNAME"
[ "$TARGET_USER" != "root" ] || die "refusing to protect root's own account - pass --user USERNAME for the actual desktop user"
getent passwd "$TARGET_USER" >/dev/null 2>&1 || die "no such user: $TARGET_USER"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || die "user $TARGET_USER has no valid home directory (got: '$TARGET_HOME')"

suggest_toolchain_install() {
    local id="unknown"
    [ -f /etc/os-release ] && id="$(. /etc/os-release && echo "$ID")"
    case "$id" in
        ubuntu|debian) echo "  apt update && apt install -y cargo build-essential" ;;
        fedora)        echo "  dnf install -y cargo gcc" ;;
        rhel|rocky|almalinux|centos) echo "  dnf install -y --allowerasing cargo gcc  (enable EPEL/CRB first if not found)" ;;
        arch)          echo "  pacman -Sy --noconfirm rust base-devel" ;;
        opensuse*|sles) echo "  zypper install -y cargo gcc" ;;
        *)              echo "  install a Rust toolchain (cargo, rustc) and a C compiler for your distro, or via https://rustup.rs" ;;
    esac
}

missing_tools=()
command -v cargo >/dev/null 2>&1 || missing_tools+=("cargo")
command -v rustc >/dev/null 2>&1 || missing_tools+=("rustc")
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || missing_tools+=("a C compiler (cc/gcc/clang, needed to link)")
if [ "${#missing_tools[@]}" -gt 0 ]; then
    log_err "missing build tools: ${missing_tools[*]}"
    log_info "on this system, try:"
    suggest_toolchain_install
    exit 1
fi

log_ok "preflight checks passed (protecting user: $TARGET_USER, home: $TARGET_HOME)"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
log_info "building warden --release from $SCRIPT_DIR (this can take a minute or two)"
if ! ( cd "$SCRIPT_DIR" && cargo build --release --bin warden ); then
    die "build failed - see cargo output above"
fi

BUILT_BIN="$SCRIPT_DIR/target/release/warden"
[ -x "$BUILT_BIN" ] || die "build reported success but $BUILT_BIN is missing or not executable"
log_ok "build succeeded: $BUILT_BIN"

# ---------------------------------------------------------------------------
# Stop any existing instance before replacing files (upgrade-safe).
# ---------------------------------------------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    log_info "stopping existing $SERVICE_NAME service before upgrading"
    systemctl stop "$SERVICE_NAME"
fi

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------
install -m 0755 -o root -g root "$BUILT_BIN" "$BIN_DEST"
log_ok "installed binary to $BIN_DEST"

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
install -d -m 0755 -o root -g root "$CONFIG_DIR"
install -d -m 0700 -o root -g root "$QUARANTINE_DIR"
log_ok "created $CONFIG_DIR, $QUARANTINE_DIR"

# The set of directories Warden watches by default (mirrors
# RansomwareConfig::resolve_defaults in warden-ransomware/src/config.rs -
# keep the two in sync). Created if missing, owned by the target user, so a
# freshly-provisioned workstation is protected from day one instead of
# silently watching nothing until the user manually creates ~/Documents.
DEFAULT_WATCH_SUBDIRS=(Documents Desktop Downloads Pictures Videos Music)
WATCH_DIRS=()
for d in "${DEFAULT_WATCH_SUBDIRS[@]}"; do
    full="$TARGET_HOME/$d"
    if [ ! -d "$full" ]; then
        install -d -m 0755 -o "$TARGET_USER" -g "$TARGET_USER" "$full"
        log_warn "$full did not exist, created it"
    fi
    WATCH_DIRS+=("$full")
done

# ---------------------------------------------------------------------------
# Config - never overwrite an existing one (preserves tuned settings across
# a reinstall/upgrade).
# ---------------------------------------------------------------------------
if [ -f "$CONFIG_FILE" ]; then
    log_warn "$CONFIG_FILE already exists, leaving it untouched (--user/--enforce arguments to this run are ignored for its contents)"
    # Reflect what's actually configured, not this run's (possibly ignored)
    # arguments, in the systemd ReadWritePaths drop-in below - otherwise a
    # reinstall after target_user or watch_dirs changed by hand would grant
    # access to the wrong set of directories.
    existing_user="$(grep -E '^target_user' "$CONFIG_FILE" 2>/dev/null | sed -E 's/^target_user[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/')"
    if [ -n "$existing_user" ] && getent passwd "$existing_user" >/dev/null 2>&1; then
        eh="$(getent passwd "$existing_user" | cut -d: -f6)"
        if [ -n "$eh" ] && [ -d "$eh" ]; then
            TARGET_USER="$existing_user"
            TARGET_HOME="$eh"
            WATCH_DIRS=()
            for d in "${DEFAULT_WATCH_SUBDIRS[@]}"; do
                [ -d "$eh/$d" ] && WATCH_DIRS+=("$eh/$d")
            done
            log_info "using target_user from existing config for systemd permissions: $TARGET_USER"
        fi
    fi
else
    cat > "$CONFIG_FILE" <<EOF
mode = "$MODE"
target_user = "$TARGET_USER"

[ransomware]
EOF
    chmod 0644 "$CONFIG_FILE"
    log_ok "wrote $CONFIG_FILE (mode=$MODE, target_user=$TARGET_USER)"
    if [ "$MODE" = "enforce" ]; then
        log_warn "starting directly in enforce mode - make sure you've already validated this against false positives (see README)"
    fi
fi

# ---------------------------------------------------------------------------
# systemd unit + a drop-in granting write access to the directories this
# specific install actually needs (ProtectSystem=strict in the base unit
# makes everything else read-only - see systemd/warden.service).
# ---------------------------------------------------------------------------
install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DEST"
install -d -m 0755 "$UNIT_DROPIN_DIR"

rwpaths="$QUARANTINE_DIR"
for d in "${WATCH_DIRS[@]}"; do
    rwpaths+=" $d"
done

cat > "$UNIT_DROPIN_DIR/local.conf" <<EOF
# Generated by install.sh - adds write access (on top of the base unit's
# ProtectSystem=strict) to this install's actual quarantine and watched
# directories. Re-run install.sh after changing target_user or adding watch
# directories by hand to regenerate.
[Service]
ReadWritePaths=$rwpaths
EOF
log_ok "installed systemd unit + ReadWritePaths drop-in ($rwpaths)"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
log_ok "enabled $SERVICE_NAME (will start on boot)"

log_info "starting $SERVICE_NAME"
if ! systemctl restart "$SERVICE_NAME"; then
    log_err "systemctl restart $SERVICE_NAME failed"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
log_info "verifying installation"

ready=0
for _ in $(seq 1 20); do
    if systemctl is-active --quiet "$SERVICE_NAME" && journalctl -u "$SERVICE_NAME" --no-pager 2>/dev/null | grep -q "warden ready"; then
        ready=1
        break
    fi
    sleep 0.5
done

if [ "$ready" -ne 1 ]; then
    log_err "$SERVICE_NAME did not reach the ready state in time"
    log_info "service status:"
    systemctl status "$SERVICE_NAME" --no-pager || true
    log_info "recent logs:"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
    exit 1
fi

installed_version="$("$BIN_DEST" --version 2>/dev/null || echo unknown)"
enabled_state="$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo unknown)"

echo
log_ok "Warden is installed and running"
cat <<EOF

  Binary:          $BIN_DEST ($installed_version)
  Config:          $CONFIG_FILE
  Service:         $(systemctl is-active "$SERVICE_NAME") / enabled=$enabled_state
  Protecting:      $TARGET_USER ($TARGET_HOME)
  Quarantine dir:  $QUARANTINE_DIR

  Live logs:       journalctl -u $SERVICE_NAME -f
  Edit config:     $CONFIG_FILE (then: systemctl restart $SERVICE_NAME)

EOF

if [ "$MODE" = "monitor" ] && ! [ -f "$CONFIG_FILE.preexisting" ]; then
    cat <<EOF
  Currently in MONITOR mode: nothing gets killed or quarantined yet, only
  logged and desktop-notified. Let it run for a while, then switch "mode"
  to "enforce" in $CONFIG_FILE and run: systemctl restart $SERVICE_NAME

EOF
fi

log_ok "done"
