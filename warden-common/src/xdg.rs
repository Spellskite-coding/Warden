use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::warn;

/// Resolves one of the target user's real XDG user directories (Desktop,
/// Downloads, Documents, Pictures, Videos, Music, ...) by reading
/// `~/.config/user-dirs.dirs` - the file `xdg-user-dirs-update` writes on
/// every desktop session that has ever run it (a dependency of every
/// major DE's session startup, so effectively always present on a real
/// workstation) - falling back to `home.join(english_default)` when that
/// file is missing entirely (a server, a bare window manager, or a
/// session that genuinely never ran the tool) or doesn't list `xdg_key`.
///
/// This matters beyond cosmetics: on any non-English desktop locale
/// (French, German, Spanish, ...) the REAL Desktop/Downloads/Pictures/
/// Videos/Music directories are named in that language (`Bureau`,
/// `Téléchargements`, `Images`, `Vidéos`, `Musique` on a French system) -
/// a hardcoded English directory name silently never matches any of
/// them. Confirmed live on a French-locale KDE Plasma Debian install
/// before this fix: a ransomware burst dropped into the real `Bureau`
/// folder, and an EICAR test file dropped into the real
/// `Téléchargements` folder, were both completely invisible to the
/// ransomware and YARA modules, which only ever watched the
/// coincidentally-English-named, actually-unused `Desktop`/`Downloads`
/// directories that also happen to exist (created by other tooling, but
/// not where the desktop environment or any application actually points
/// the user).
pub fn resolve_dir(home: &Path, xdg_key: &str, english_default: &str) -> PathBuf {
    let resolved = parse_user_dirs_file(home).and_then(|dirs| dirs.get(xdg_key).cloned());
    match resolved {
        // `~/.config/user-dirs.dirs` is fully writable by the target
        // user, so this is the one resolution a review found genuinely
        // dangerous to accept unconditionally: it's this function's
        // result that later becomes a `fanotify`-watched (and, in
        // Enforce mode, auto-quarantined) directory - handing it back
        // the filesystem root turns "watch Downloads" into "watch and
        // potentially quarantine every file on the machine" the moment
        // anything writes to it, entirely at the target user's own
        // discretion (no root/admin action involved). No legitimate XDG
        // config ever points at `/` itself, so refusing this one exact
        // case and falling back to the safe default costs nothing real.
        //
        // This does NOT close every risk from trusting a user-writable
        // config for a security-relevant default - a redirect to some
        // OTHER attacker-chosen absolute path (rather than an outright
        // narrowing of true Downloads) can still steer *away* from the
        // real Downloads folder, same tension `package_manager.rs` had
        // with process identity vs. location. Left as a known, accepted
        // residual limitation (see PROGRESS.md) rather than silently
        // treated as fully solved: narrowing what absolute paths are
        // accepted here would also break the legitimate case this whole
        // mechanism exists for (a real Downloads folder on another
        // mount), which is a bigger design tradeoff than this pass makes
        // alone.
        Some(dir) if dir == Path::new("/") => {
            warn!(xdg_key, "user-dirs.dirs resolved to the filesystem root - refusing to use it, falling back to the safe default");
            home.join(english_default)
        }
        Some(dir) => dir,
        None => home.join(english_default),
    }
}

/// Parses `~/.config/user-dirs.dirs`. The format (documented in the
/// comment header `xdg-user-dirs-update` itself writes into every such
/// file) is deliberately restrictive: each line is
/// `XDG_xxx_DIR="$HOME/yyy"` or `XDG_xxx_DIR="/yyy"` - never a shell
/// expression to evaluate, so `$HOME` is the only substitution handled
/// here, literally, not via a shell.
fn parse_user_dirs_file(home: &Path) -> Option<HashMap<String, PathBuf>> {
    let content = std::fs::read_to_string(home.join(".config/user-dirs.dirs")).ok()?;
    let mut dirs = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        if !key.starts_with("XDG_") || !key.ends_with("_DIR") {
            continue;
        }
        let value = value.trim().trim_matches('"');

        let resolved = if let Some(rest) = value.strip_prefix("$HOME") {
            if rest.is_empty() { home.to_path_buf() } else { home.join(rest.trim_start_matches('/')) }
        } else {
            PathBuf::from(value)
        };
        dirs.insert(key.to_string(), resolved);
    }
    Some(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_home(suffix: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("warden-xdg-test-{suffix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        home
    }

    #[test]
    fn resolves_localized_names_from_a_real_user_dirs_file() {
        let home = scratch_home("localized");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(
            home.join(".config/user-dirs.dirs"),
            "# comment line, ignored\nXDG_DESKTOP_DIR=\"$HOME/Bureau\"\nXDG_DOWNLOAD_DIR=\"$HOME/Téléchargements\"\n",
        )
        .unwrap();

        assert_eq!(resolve_dir(&home, "XDG_DESKTOP_DIR", "Desktop"), home.join("Bureau"));
        assert_eq!(resolve_dir(&home, "XDG_DOWNLOAD_DIR", "Downloads"), home.join("Téléchargements"));
        // Present in the underlying spec but absent from THIS file -> falls back.
        assert_eq!(resolve_dir(&home, "XDG_MUSIC_DIR", "Music"), home.join("Music"));

        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn falls_back_to_english_default_when_no_user_dirs_file_exists() {
        let home = scratch_home("none");
        assert_eq!(resolve_dir(&home, "XDG_DESKTOP_DIR", "Desktop"), home.join("Desktop"));
    }

    /// Regression test for the finding that `XDG_DOWNLOAD_DIR="/"` (a
    /// value the target user's own, fully user-writable
    /// `user-dirs.dirs` can set) turned the watched "Downloads" scope
    /// into the entire filesystem - a self-inflictable, root-privileged
    /// DoS/scope-creep with no admin action required.
    #[test]
    fn refuses_filesystem_root_and_falls_back_to_the_default() {
        let home = scratch_home("root-escape");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(".config/user-dirs.dirs"), "XDG_DOWNLOAD_DIR=\"/\"\n").unwrap();
        assert_eq!(resolve_dir(&home, "XDG_DOWNLOAD_DIR", "Downloads"), home.join("Downloads"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn handles_an_absolute_path_entry() {
        let home = scratch_home("absolute");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(".config/user-dirs.dirs"), "XDG_DOWNLOAD_DIR=\"/mnt/data/dl\"\n").unwrap();
        assert_eq!(resolve_dir(&home, "XDG_DOWNLOAD_DIR", "Downloads"), PathBuf::from("/mnt/data/dl"));
        std::fs::remove_dir_all(&home).ok();
    }
}
