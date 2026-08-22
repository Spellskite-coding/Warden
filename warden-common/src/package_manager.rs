use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Every directory a real system package manager binary can legitimately
/// live in - the same list `warden-privesc` uses for "this is a trusted
/// install location", reused here for the same reason. Canonicalized once
/// (usr-merge distros symlink `/bin`/`/sbin` to their `/usr` counterparts)
/// and cached, since `is_active()` runs on every persistence event and
/// every privesc poll tick.
const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"];

fn canonical_system_bin_dirs() -> &'static [PathBuf] {
    static DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    DIRS.get_or_init(|| {
        let mut seen = std::collections::HashSet::new();
        SYSTEM_BIN_DIRS.iter().filter_map(|d| std::fs::canonicalize(d).ok()).filter(|d| seen.insert(d.clone())).collect()
    })
}

/// `/proc/<pid>/comm` names (kernel-truncated to 15 characters) of common
/// package managers across the distro test matrix. A trusted installer
/// legitimately does exactly the same shape of thing Warden otherwise
/// treats as suspicious by default: drop a new cron job, sudoers grant,
/// systemd unit, autostart entry, or setuid helper.
const PACKAGE_MANAGER_PROCESS_NAMES: &[&str] = &[
    // Debian/Ubuntu
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "unattended-upgr", // real name "unattended-upgrade", truncated by the kernel
    // Fedora/RHEL/Rocky/Alma
    "dnf",
    "dnf-automatic",
    "yum",
    "rpm",
    "packagekitd",
    // Arch
    "pacman",
    // openSUSE
    "zypper",
    // Cross-distro
    "flatpak",
    "snapd",
];

/// Whether a system package manager is currently running, checked by
/// scanning `/proc/*` for a known process name. Used to suppress
/// Warden's own auto-quarantine of brand-new files in Enforce mode
/// (persistence's `UnitDir` kind, privesc's new-setuid-binary path)
/// while a trusted installer is legitimately at work.
///
/// Deliberately process-name based rather than a distro-specific lock
/// file (`/var/lib/dpkg/lock-frontend` on Debian, `/var/lib/rpm/.rpm.lock`
/// on Fedora/Rocky, `/var/lib/pacman/db.lck` on Arch, ...): one check
/// that works the same way on every distro in the test matrix, instead
/// of a growing list of per-distro lock paths to keep in sync. A
/// point-in-time check, not a window: a file created in the brief gap
/// right after the package manager process exits could still be
/// quarantined, an accepted trade-off rather than added complexity for
/// a race that routine upgrades essentially never hit in practice (the
/// watched files are written well before dpkg/rpm/pacman's own process
/// exits).
///
/// Checks three independent signals and requires all to agree: `comm`
/// (fast, but any process can rename itself to "apt" via
/// `prctl(PR_SET_NAME)`), the basename of the process's real executable
/// path via `/proc/<pid>/exe` (kernel-resolved, not spoofable by the
/// process itself), and - the one that actually matters - that `exe`'s
/// *directory* canonicalizes to one of `SYSTEM_BIN_DIRS`.
///
/// A real red-team finding, not a hypothetical: an earlier version of
/// this function stopped at the first two checks, on the reasoning that
/// a process can't fake `exe`'s basename without literally being that
/// binary. That reasoning missed the actual attack: `cp /bin/sleep
/// /tmp/apt && /tmp/apt 300 &` makes both `comm` AND `exe`'s basename
/// read "apt", with neither signal ever inspecting *where* that binary
/// actually lives. Confirmed exploitable end-to-end on a live VM: a
/// `/tmp/apt` decoy process running during a real
/// `/etc/cron.d/<persistence>` drop suppressed auto-quarantine in
/// Enforce mode exactly as the real package manager would have. The
/// directory check closes it - `/tmp` (or anywhere else a decoy could be
/// dropped) can never canonicalize to a `SYSTEM_BIN_DIRS` entry, no
/// matter what the binary is named or renamed to.
pub fn is_active() -> bool {
    let system_bin_dirs = canonical_system_bin_dirs();
    let Ok(entries) = fs::read_dir("/proc") else { return false };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let path = entry.path();

        let Ok(comm) = fs::read_to_string(path.join("comm")) else { continue };
        if !PACKAGE_MANAGER_PROCESS_NAMES.contains(&comm.trim()) {
            continue;
        }

        let Ok(exe) = fs::read_link(path.join("exe")) else { continue };
        let Some(exe_name) = exe.file_name().and_then(|n| n.to_str()) else { continue };
        if !PACKAGE_MANAGER_PROCESS_NAMES.contains(&exe_name) {
            continue;
        }

        let Some(exe_dir) = exe.parent() else { continue };
        let Ok(exe_dir) = exe_dir.canonicalize() else { continue };
        if system_bin_dirs.contains(&exe_dir) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_does_not_panic_and_returns_a_bool() {
        let _: bool = is_active();
    }

    /// Regression test for the red-team-confirmed bypass: a decoy binary
    /// named "apt" running from `/tmp` (or any non-`SYSTEM_BIN_DIRS`
    /// location) must not make `is_active()` return true, even though it
    /// passes both the `comm` and `exe`-basename checks. Reproduces the
    /// exact technique from `test_pkgmgr_spoof.sh`: copy a real binary to
    /// a path whose basename is a package manager name, then run it.
    #[test]
    fn decoy_binary_outside_system_bin_dirs_does_not_count_as_active() {
        // A pid-namespaced subdirectory so the copy's basename can be
        // exactly "apt" (needed to pass the comm/exe-basename checks)
        // without colliding with a parallel test run.
        let dir = std::env::temp_dir().join(format!("warden-pkgmgr-spoof-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creating scratch dir for the decoy");
        let named_apt = dir.join("apt");
        std::fs::copy("/bin/sleep", &named_apt).expect("copying /bin/sleep to build the decoy");

        // The kernel sets `comm` and `exe`'s basename from the path used
        // to exec, so naming the copy "apt" is enough to pass both of
        // those checks - no prctl(PR_SET_NAME) needed, exactly like
        // `test_pkgmgr_spoof.sh`'s `cp /bin/sleep /tmp/apt`. On overlayfs
        // (the norm inside a Docker build container), executing a file
        // immediately after writing it can transiently fail with
        // `ETXTBSY` until the copy-up settles - not a real "already
        // running" conflict, so a few short retries clear it reliably.
        let mut child = None;
        for attempt in 0..10 {
            match std::process::Command::new(&named_apt).arg("2").spawn() {
                Ok(c) => {
                    child = Some(c);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 9 => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("spawning decoy process: {e}"),
            }
        }
        let mut child = child.expect("spawning decoy process after retries");
        std::thread::sleep(std::time::Duration::from_millis(200));

        assert!(!is_active(), "a decoy binary named 'apt' running from outside SYSTEM_BIN_DIRS must not be treated as the real package manager");

        child.kill().ok();
        child.wait().ok();
        std::fs::remove_dir_all(&dir).ok();
    }
}
