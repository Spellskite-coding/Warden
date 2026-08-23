#!/usr/bin/env bash
#
# Warden EDR uninstaller.
#
# Removes what install.sh put on this machine: systemd units, binaries,
# and (best-effort) the desktop GUI's icon/launcher entry. By default,
# leaves config (/etc/warden) and state (/var/lib/warden - quarantine,
# history, the honeypot seed) untouched: quarantine can hold the only
# copy of something a real incident actually flagged, so removing it is
# a separate, explicit, confirmed action (--purge), never a side effect
# of "I don't want the daemon running anymore."
#
# Every path this script acts on is a fixed, hardcoded constant below -
# never built from a variable that could be empty or attacker-influenced
# - specifically so a typo or unset variable can never widen a `rm -rf`
# into somewhere it shouldn't be. Safe to run more than once: every step
# tolerates "already gone" rather than failing the whole script over it.

set -euo pipefail

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/warden"
STATE_DIR="/var/lib/warden"
SYSTEMD_DIR="/etc/systemd/system"
SHARE_DIR="/usr/share/warden"

log()  { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m==> warning:\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m==> error:\033[0m $*" >&2; exit 1; }

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--purge] [-y|--yes]

  --purge   Also remove $CONFIG_DIR (config, exceptions) and $STATE_DIR
            (quarantine, history, honeypot seed). Without this flag,
            those are left on disk after uninstalling.
  -y, --yes Skip the confirmation prompt before --purge deletes them.
EOF
            exit 0
            ;;
        *) die "unknown argument: $arg (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must be run as root (it stops system services and removes root-owned files)"

# ---------------------------------------------------------------------------
# Step 1: stop and disable services FIRST, before touching any file -
# same reasoning as install.sh's own "stop before writing" step: with
# Warden still running while its own unit files or binaries disappear out
# from under it, nothing guarantees a clean shutdown, and a couple of the
# very files this script removes are directories persistence actively
# watches.
# ---------------------------------------------------------------------------

log "stopping and disabling Warden services"
systemctl stop warden.service warden-exec.service warden-network.service 2>/dev/null || true
systemctl disable warden.service warden-exec.service warden-network.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 2: systemd units
# ---------------------------------------------------------------------------

log "removing systemd units"
rm -f "$SYSTEMD_DIR/warden.service" "$SYSTEMD_DIR/warden-exec.service" "$SYSTEMD_DIR/warden-network.service"
rm -f "$SYSTEMD_DIR/warden.service.d/10-paths.conf"
rmdir "$SYSTEMD_DIR/warden.service.d" 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed warden.service warden-exec.service warden-network.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 3: binaries
# ---------------------------------------------------------------------------

log "removing binaries from $BIN_DIR"
rm -f "$BIN_DIR/warden" "$BIN_DIR/warden-notify-helper" "$BIN_DIR/warden-gui" "$BIN_DIR/warden-exec" "$BIN_DIR/warden-network"

# ---------------------------------------------------------------------------
# Step 4: GUI - icon, .desktop entry, branding asset
# ---------------------------------------------------------------------------

log "removing GUI icon and desktop entry (if present)"
rm -f /usr/share/applications/warden-gui.desktop
for sz in 16 32 48 64 128 256; do
    rm -f "/usr/share/icons/hicolor/${sz}x${sz}/apps/warden.png"
done
rm -f /usr/share/icons/hicolor/scalable/apps/warden.svg
rm -rf "$SHARE_DIR"

gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Step 5: config + state - only with --purge, and only after confirmation
# ---------------------------------------------------------------------------

if [ "$PURGE" -eq 1 ]; then
    echo
    warn "--purge will permanently delete:"
    warn "  $CONFIG_DIR (config.toml, the shared exceptions list)"
    warn "  $STATE_DIR (quarantined files, detection history, the honeypot seed)"
    warn "Quarantined files may be the only surviving copy of something a real detection flagged."
    if [ "$ASSUME_YES" -ne 1 ]; then
        if [ -t 0 ]; then
            read -r -p "Type 'yes' to permanently delete these: " reply
        else
            reply=""
            warn "not running interactively and -y/--yes was not given - skipping the purge."
        fi
        if [ "$reply" != "yes" ]; then
            warn "purge skipped (confirmation not given). $CONFIG_DIR and $STATE_DIR left in place."
            PURGE=0
        fi
    fi
fi

if [ "$PURGE" -eq 1 ]; then
    log "removing $CONFIG_DIR and $STATE_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$STATE_DIR"
else
    log "config ($CONFIG_DIR) and state ($STATE_DIR) left in place - re-run with --purge to remove them too"
fi

echo
log "Warden uninstalled."
# Honeypot decoy folders (a per-machine randomized name inside
# Documents/Desktop/Downloads/etc. and one at the top of $HOME,
# containing a single passwords_export.csv or releve_compte.csv) live in
# the protected user's own home directory, not under $STATE_DIR - this
# script does not remove them. Reconstructing their exact names would
# mean duplicating warden-ransomware::honeypot's word-selection logic
# here in bash, a second implementation that could silently drift out of
# sync with the real one; pattern-matching against arbitrary directories
# inside a live user's home to delete them automatically is exactly the
# kind of guess a cleanup script should not make. They are harmless if
# left behind - and easy to spot in the meantime, so we just say so.
echo "  Note: any honeypot decoy folders Warden created under your home directory"
echo "        (an unfamiliar folder in Documents/Desktop/etc. holding a single"
echo "        passwords_export.csv, or one at the top of \$HOME holding releve_compte.csv)"
echo "        are not removed by this script and can be deleted by hand if you want."
