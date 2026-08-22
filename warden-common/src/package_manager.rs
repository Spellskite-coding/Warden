use std::fs;
use std::path::{Path, PathBuf};
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
/// Whether `exe_name` is an interpreter binary that a legitimate
/// package-manager script is known to run under. `unattended-upgrade` is
/// the motivating case: it's a Python script (shebang `#!/usr/bin/python3`),
/// so its `/proc/<pid>/exe` resolves to the interpreter that executed it,
/// never to the script file itself - the exact same interpreter-vs-script
/// distinction already worked around in `warden-exec`'s exec-event
/// handling. The version-suffixed check (`python3.11`, `python3.13`, ...)
/// matters because `/usr/bin/python3` itself is frequently just a symlink,
/// and the *resolved* `exe` target on the distros in the test matrix is
/// the versioned binary, not the `python3` name.
fn is_known_interpreter(exe_name: &str) -> bool {
    exe_name == "python3" || exe_name.starts_with("python3.")
}

/// For a process whose `exe` is a known interpreter rather than the
/// package manager itself, extracts the script path it was actually
/// invoked with. Reads `argv[1]` from `/proc/<pid>/cmdline`: when the
/// kernel runs a shebang script (`binfmt_script`), it re-executes as
/// `<interpreter> <script-path> <original-args...>`, so the script's own
/// path is always the interpreter's first argument for the simple,
/// no-`env`-indirection shebang line `unattended-upgrade` actually uses.
fn interpreted_script_path(proc_path: &Path) -> Option<PathBuf> {
    let cmdline = fs::read(proc_path.join("cmdline")).ok()?;
    let mut args = cmdline.split(|&b| b == 0).filter(|s| !s.is_empty());
    args.next()?; // argv[0]: the interpreter itself
    let script = args.next()?;
    Some(PathBuf::from(std::str::from_utf8(script).ok()?))
}

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

        let Some(exe_dir) = exe.parent() else { continue };
        let Ok(exe_dir) = exe_dir.canonicalize() else { continue };
        if !system_bin_dirs.contains(&exe_dir) {
            continue;
        }

        if PACKAGE_MANAGER_PROCESS_NAMES.contains(&exe_name) {
            return true;
        }

        // `exe` resolving to a real interpreter in a system bin dir only
        // proves the interpreter is genuine - it says nothing about which
        // script it's running, and an attacker who controls the exec call
        // controls `argv` (`python3 /tmp/evil` can present its script arg
        // as anything, the same way `comm` can be spoofed via
        // `prctl(PR_SET_NAME)`). So the script path pulled from `cmdline`
        // gets the exact same two checks as `exe` above: known name *and*
        // its own directory canonicalizes into `SYSTEM_BIN_DIRS` - a
        // decoy at `/tmp/unattended-upgrade` still can't pass that.
        if is_known_interpreter(exe_name) {
            if let Some(script) = interpreted_script_path(&path) {
                let script_name_ok = script.file_name().and_then(|n| n.to_str()).is_some_and(|n| PACKAGE_MANAGER_PROCESS_NAMES.contains(&n));
                let script_dir_ok = script.parent().and_then(|d| d.canonicalize().ok()).is_some_and(|d| system_bin_dirs.contains(&d));
                if script_name_ok && script_dir_ok {
                    return true;
                }
            }
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

    #[test]
    fn recognizes_versioned_python_interpreter_names() {
        assert!(is_known_interpreter("python3"));
        assert!(is_known_interpreter("python3.11"));
        assert!(is_known_interpreter("python3.13"));
        assert!(!is_known_interpreter("python2"));
        assert!(!is_known_interpreter("python"));
        assert!(!is_known_interpreter("perl"));
    }

    /// Regression test for a real red-team-confirmed gap: `unattended-upgrade`
    /// is a Python script, so `/proc/<pid>/exe` resolves to the `python3`
    /// interpreter that ran it, not to the script - `is_active()` never
    /// recognized a live `unattended-upgrade` run at all before the
    /// interpreter fallback was added. `interpreted_script_path` is what
    /// recovers the actual script path from `cmdline` in that case; this
    /// exercises it directly against a synthesized `cmdline` (real
    /// `/proc/<pid>/cmdline` is NUL-separated argv, exactly reproduced here)
    /// rather than needing to spawn and inspect a real process.
    #[test]
    fn interpreted_script_path_reads_argv1_from_cmdline() {
        let dir = std::env::temp_dir().join(format!("warden-pkgmgr-cmdline-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creating scratch dir");
        let mut cmdline = Vec::new();
        cmdline.extend_from_slice(b"/usr/bin/python3\0");
        cmdline.extend_from_slice(b"/usr/bin/unattended-upgrade\0");
        cmdline.extend_from_slice(b"--dry-run\0");
        std::fs::write(dir.join("cmdline"), &cmdline).expect("writing synthetic cmdline");

        let script = interpreted_script_path(&dir).expect("should parse a script path out of argv");
        assert_eq!(script, PathBuf::from("/usr/bin/unattended-upgrade"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn interpreted_script_path_returns_none_when_there_is_no_second_argv() {
        let dir = std::env::temp_dir().join(format!("warden-pkgmgr-cmdline-noarg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creating scratch dir");
        std::fs::write(dir.join("cmdline"), b"/usr/bin/python3\0").expect("writing synthetic cmdline");

        assert!(interpreted_script_path(&dir).is_none());

        std::fs::remove_dir_all(&dir).ok();
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
