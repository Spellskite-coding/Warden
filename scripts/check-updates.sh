#!/usr/bin/env bash
# Checks whether Warden's toolchains or dependencies need attention:
# known vulnerabilities in either cargo workspace, and whether the pinned
# LLVM version in docker/Dockerfile.build-ebpf still matches what the
# active nightly toolchain actually bundles (a drift here silently breaks
# bpf-linker with a cryptic error - see PROGRESS.md's eBPF toolchain
# section for why this specific check exists).
#
# Everything runs inside Docker, never on the host - see PROGRESS.md's
# "Regle absolue de workflow".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
WARDEN_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_IMAGE="warden-build:rockylinux"
EBPF_IMAGE="warden-build:ebpf"

if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_RESET=""
fi
log_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$1"; }
log_ok()   { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
log_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1"; }

NEEDS_ATTENTION=0

# ---------------------------------------------------------------------------
# eBPF toolchain: pinned LLVM vs what the active nightly bundles
# ---------------------------------------------------------------------------
check_llvm_nightly_match() {
    log_info "checking eBPF toolchain: pinned LLVM vs active nightly's bundled LLVM"

    if ! docker image inspect "$EBPF_IMAGE" >/dev/null 2>&1; then
        log_warn "$EBPF_IMAGE not built yet, skipping (docker build -t $EBPF_IMAGE -f docker/Dockerfile.build-ebpf .)"
        return
    fi

    local pinned
    pinned="$(grep -oE 'llvm\.sh[[:space:]]+[0-9]+' "$WARDEN_DIR/docker/Dockerfile.build-ebpf" | grep -oE '[0-9]+$' | head -1)"
    if [ -z "$pinned" ]; then
        log_warn "could not determine pinned LLVM version from Dockerfile.build-ebpf, skipping"
        return
    fi

    local actual
    actual="$(docker run --rm "$EBPF_IMAGE" bash -c 'rustup run nightly rustc --version --verbose' 2>/dev/null | grep -oE 'LLVM version: [0-9]+' | grep -oE '[0-9]+' || true)"
    if [ -z "$actual" ]; then
        log_warn "could not determine active nightly's LLVM version, skipping"
        return
    fi

    if [ "$pinned" = "$actual" ]; then
        log_ok "LLVM match: nightly bundles LLVM $actual, Dockerfile.build-ebpf pins bpf-linker to LLVM $pinned"
    else
        log_err "LLVM MISMATCH: active nightly bundles LLVM $actual, but Dockerfile.build-ebpf pins LLVM $pinned"
        log_info "this will break bpf-linker with a cryptic 'ERROR llvm: Invalid record' at link time"
        log_info "fix: in docker/Dockerfile.build-ebpf, replace every occurrence of '$pinned' with '$actual'"
        log_info "  (the llvm.sh call, libpolly-*-dev, the PATH entry, LLVM_SYS_*_PREFIX, and --features llvm-$actual)"
        log_info "  then rebuild: docker build -t $EBPF_IMAGE -f docker/Dockerfile.build-ebpf ."
        NEEDS_ATTENTION=1
    fi
}

# ---------------------------------------------------------------------------
# Known-vulnerability scan via cargo-audit, run against each workspace's
# Cargo.lock. Uses the plain stable-toolchain build image for both - audit
# only reads Cargo.lock and queries the advisory database, it never
# compiles anything BPF-specific, so it doesn't need the eBPF toolchain.
# ---------------------------------------------------------------------------
check_cargo_audit() {
    local workspace_dir="$1" label="$2"

    log_info "cargo audit: $label"

    local status=0
    docker run --rm -v "$WARDEN_DIR:/build" \
        -v warden-cargo-registry:/usr/local/cargo/registry \
        -v warden-cargo-home:/usr/local/cargo \
        -v warden-rustup-home:/usr/local/rustup \
        -w "/build/$workspace_dir" "$BUILD_IMAGE" \
        bash -c 'command -v cargo-audit >/dev/null 2>&1 || { echo "cargo-audit not installed - run: cargo install cargo-audit" >&2; exit 2; }; cargo audit' \
        || status=$?

    if [ "$status" -eq 0 ]; then
        log_ok "$label: no known vulnerabilities"
    elif [ "$status" -eq 2 ]; then
        log_warn "$label: cargo-audit is not installed, skipping"
    else
        log_err "$label: cargo audit reported findings (see above)"
        NEEDS_ATTENTION=1
    fi
}

check_llvm_nightly_match
echo
check_cargo_audit "." "main workspace"
echo
check_cargo_audit "ebpf-probe" "ebpf-probe workspace"
echo

if [ "$NEEDS_ATTENTION" -eq 1 ]; then
    log_err "one or more checks need attention - see above"
    exit 1
fi
log_ok "all checks passed"
