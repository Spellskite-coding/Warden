use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use warden_common::event::Severity;

/// What kind of persistence surface a watched location is, which decides
/// whether Enforce mode is allowed to act on it automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A file whose *edits* we only ever observe. There is no PID to act
    /// on (inotify never reports who wrote a file, unlike fanotify), and
    /// auto-reverting a shell startup file or `authorized_keys` risks
    /// destroying a legitimate edit the user just made - so this is
    /// always report-only, in both Monitor and Enforce mode.
    Dotfile,
    /// A directory holding self-contained unit-like files (cron jobs, XDG
    /// autostart entries, systemd units). Nothing legitimate stores real
    /// work *inside* one of these files - it either is the persistence
    /// mechanism or it isn't - so a brand new file appearing here can be
    /// safely quarantined outright in Enforce mode. Edits to a
    /// *pre-existing* file of this kind are still report-only, same
    /// reasoning as `Dotfile`.
    UnitDir,
    /// A systemd drop-in override directory (`<unit>.service.d/`,
    /// `<unit>.timer.d/`) appearing directly inside an already-watched
    /// unit directory. A review pointed out this was a complete, silent
    /// blind spot: `systemctl edit <unit>` on any pre-existing unit
    /// (not just one Warden's own `UnitDir` logic already watches for
    /// brand-new unit files) drops an `override.conf` with its own
    /// `ExecStart=`/`ExecStartPost=` into a *subdirectory*, and inotify
    /// on a directory isn't recursive - the parent dir watch sees the
    /// new subdirectory's name, but nothing written *inside* it
    /// afterward, and the existing content-diffing logic doesn't apply
    /// to a directory at all. This only catches the drop-in directory's
    /// first appearance (a real, working signal - genuinely nothing
    /// legitimate creates one of these outside a deliberate admin
    /// action), not edits to what's inside it afterward; report-only in
    /// both modes, same reasoning as `Dotfile`, since there's no single
    /// file here safe to act on automatically.
    DropinOverrideDir,
}

#[derive(Debug, Clone)]
pub enum NameFilter {
    Exact(String),
    Suffix(&'static str),
    Any,
}

impl NameFilter {
    fn matches(&self, name: &OsStr) -> bool {
        let name = name.to_string_lossy();
        match self {
            NameFilter::Exact(n) => name == n.as_str(),
            NameFilter::Suffix(s) => name.ends_with(s),
            NameFilter::Any => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub filter: NameFilter,
    pub label: &'static str,
    pub kind: TargetKind,
    /// Baseline severity for an otherwise-unremarkable change; heuristic
    /// pattern matches on the diff content can raise it.
    pub base_severity: Severity,
}

/// One inotify watch: a directory plus every rule that applies to entries
/// directly inside it. Watching the *directory* rather than each file
/// individually matters: editors commonly save by writing a temp file and
/// renaming it over the original, which replaces the inode a
/// direct-on-file watch would have been bound to and silently stops
/// watching it. A directory watch, filtered by filename, survives that.
#[derive(Debug, Clone)]
pub struct DirWatch {
    pub dir: PathBuf,
    pub rules: Vec<Rule>,
}

impl DirWatch {
    pub fn matching_rule(&self, name: &OsStr) -> Option<&Rule> {
        self.rules.iter().find(|r| r.filter.matches(name))
    }
}

fn dotfile(name: &str, label: &'static str, severity: Severity) -> Rule {
    Rule { filter: NameFilter::Exact(name.to_string()), label, kind: TargetKind::Dotfile, base_severity: severity }
}

fn unit_suffix(suffix: &'static str, label: &'static str, severity: Severity) -> Rule {
    Rule { filter: NameFilter::Suffix(suffix), label, kind: TargetKind::UnitDir, base_severity: severity }
}

fn unit_any(label: &'static str, severity: Severity) -> Rule {
    Rule { filter: NameFilter::Any, label, kind: TargetKind::UnitDir, base_severity: severity }
}

fn unit_exact(name: String, label: &'static str, severity: Severity) -> Rule {
    Rule { filter: NameFilter::Exact(name), label, kind: TargetKind::UnitDir, base_severity: severity }
}

fn dropin_dir(label: &'static str, severity: Severity) -> Rule {
    Rule { filter: NameFilter::Suffix(".d"), label, kind: TargetKind::DropinOverrideDir, base_severity: severity }
}

/// The default set of persistence-relevant locations to watch for
/// `target_user`. Only directories that exist at startup are included -
/// this module never creates one (unlike the ransomware module's watch
/// dirs), since e.g. a missing `~/.ssh` is itself meaningful (no SSH access
/// configured yet) and system directories like `/etc/cron.d` shouldn't be
/// conjured into existence by an EDR. A directory that doesn't exist yet
/// starts being watched only after a restart, not retroactively - a known
/// gap, see PROGRESS.md.
pub fn default_dir_watches(home: &Path, target_user: &str) -> Vec<DirWatch> {
    let mut watches = Vec::new();
    let mut push = |dir: PathBuf, rules: Vec<Rule>| {
        if dir.is_dir() {
            watches.push(DirWatch { dir, rules });
        }
    };

    // Shell startup files live directly in $HOME - watched by filename,
    // not one watch per file, for the atomic-save reason above.
    push(
        home.to_path_buf(),
        vec![
            dotfile(".bashrc", "shell startup file", Severity::Medium),
            dotfile(".bash_profile", "shell startup file", Severity::Medium),
            dotfile(".bash_login", "shell startup file", Severity::Medium),
            dotfile(".profile", "shell startup file", Severity::Medium),
            dotfile(".zshrc", "shell startup file", Severity::Medium),
            dotfile(".zprofile", "shell startup file", Severity::Medium),
        ],
    );

    push(home.join(".ssh"), vec![dotfile("authorized_keys", "SSH authorized key list", Severity::High)]);

    push(home.join(".config/fish"), vec![dotfile("config.fish", "shell startup file", Severity::Medium)]);

    push(home.join(".config/autostart"), vec![unit_suffix(".desktop", "XDG autostart entry", Severity::Medium)]);

    push(
        home.join(".config/systemd/user"),
        vec![
            unit_suffix(".service", "user systemd unit", Severity::Medium),
            unit_suffix(".timer", "user systemd timer", Severity::Medium),
            dropin_dir("user systemd drop-in override directory", Severity::High),
        ],
    );

    // System-wide. /etc itself is watched only for these two specific
    // top-level files - inotify on a directory isn't recursive, so this
    // doesn't pick up the (much noisier) contents of /etc's subdirectories.
    push(
        PathBuf::from("/etc"),
        vec![
            dotfile("crontab", "system crontab", Severity::Medium),
            dotfile("ld.so.preload", "dynamic linker preload list", Severity::High),
            // The canonical sudo policy file. Even in Enforce mode this is
            // still Dotfile, not UnitDir: a malformed/reverted sudoers file
            // can lock every admin out of sudo on the box, a worse outcome
            // than leaving a privesc grant in place for a human to review.
            dotfile("sudoers", "sudo privilege policy", Severity::Critical),
        ],
    );

    push(PathBuf::from("/etc/cron.d"), vec![unit_any("cron job", Severity::Medium)]);
    // Each file here is a self-contained sudo privilege grant - same
    // reasoning as cron.d, a new one appearing is safe to quarantine
    // outright in Enforce mode.
    push(PathBuf::from("/etc/sudoers.d"), vec![unit_any("sudoers.d privilege grant", Severity::Critical)]);
    push(PathBuf::from("/etc/profile.d"), vec![unit_suffix(".sh", "shell profile script", Severity::Medium)]);
    push(PathBuf::from("/etc/xdg/autostart"), vec![unit_suffix(".desktop", "XDG autostart entry (system-wide)", Severity::Medium)]);
    push(
        PathBuf::from("/etc/systemd/system"),
        vec![
            unit_suffix(".service", "system systemd unit", Severity::Medium),
            unit_suffix(".timer", "system systemd timer", Severity::Medium),
            dropin_dir("system systemd drop-in override directory", Severity::High),
        ],
    );

    // Per-user crontab spool: Debian/Ubuntu keep it under
    // /var/spool/cron/crontabs/<user>, RHEL-family and Arch under
    // /var/spool/cron/<user> directly. At most one of these two parent
    // directories exists on a given distro.
    push(
        PathBuf::from("/var/spool/cron/crontabs"),
        vec![unit_exact(target_user.to_string(), "user crontab", Severity::Medium)],
    );
    push(PathBuf::from("/var/spool/cron"), vec![unit_exact(target_user.to_string(), "user crontab", Severity::Medium)]);

    watches
}
