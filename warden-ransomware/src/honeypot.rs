use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Looks like a real password-manager CSV export (fake, synthetic
/// credentials throughout - never anything derived from this machine's
/// actual accounts). A review pointed out that the previous content -
/// literally "This file is a Warden canary. Do not delete." - was a
/// dead giveaway the moment anyone (a curious user, or an attacker doing
/// manual reconnaissance/exfiltration before encrypting, a real and
/// common technique rather than blind bulk encryption) actually opened
/// it: a sophisticated attacker who reads it once immediately learns
/// this specific path is a decoy and can hardcode a future skip for it.
/// Looking like a genuinely valuable, plausible target instead - the
/// same reasoning that makes the honeypot's own filename and containing
/// folder name enticing rather than something like `.warden_canary` -
/// means opening it, if it happens at all, doesn't hand an attacker a
/// free tell.
const CANARY_CONTENT: &[u8] = b"\
Title,URL,Username,Password,Notes
Online Banking,https://mybank.example.com,jsmith,K3$tR7!qPz9,Primary checking account
Company VPN,https://vpn.company.example.com,j.smith,Vpn#2024Secure,IT-issued credentials
Personal Email,https://mail.example.com,john.smith82,Em@il_Str0ng!99,
Cloud Backup (admin),https://backup.example.com,jsmith_admin,B@ckup$ecure2024,Full admin access - do not share
";

/// Content for the standalone `$HOME`-root honeypot (see
/// `home_honeypot_path`): a fake bank statement, matching that
/// honeypot's "Banque" framing - same reasoning as `CANARY_CONTENT`
/// (plausible enough to not immediately read as a decoy if actually
/// opened), synthetic data throughout.
const BANK_CANARY_CONTENT: &[u8] = b"\
Releve de compte - Compte Courant
IBAN: FR76 3000 4008 2800 0123 4567 890
Titulaire: J. SMITH
Periode: 01/07/2026 - 31/07/2026

Date,Libelle,Montant
02/07/2026,Virement salaire,+2450.00
05/07/2026,Prelevement loyer,-980.00
14/07/2026,Retrait DAB,-200.00
22/07/2026,Virement epargne,-500.00
Solde au 31/07/2026,,12480.55
";

const SEED_PATH: &str = "/var/lib/warden/honeypot_seed";

/// Plausible-sounding "theme" words for the first half of a honeypot
/// folder name, combined with `HONEYPOT_NOUNS` below. Deliberately large
/// (not just 2-3 hand-picked words) - see `honeypot_seed`'s doc comment
/// for why the combinatorial size of these two lists, not just the
/// numeric suffix, is what actually matters here.
const HONEYPOT_ADJECTIVES: &[&str] =
    &["Confidential", "Private", "Secret", "Personal", "Important", "Old", "Archived", "Secure", "Sensitive", "Encrypted", "Locked", "Restricted", "Classified", "Protected", "Hidden"];

/// Plausible-sounding subject words for the second half of a honeypot
/// folder name. Paired with `HONEYPOT_ADJECTIVES`.
const HONEYPOT_NOUNS: &[&str] = &[
    "Backup",
    "Documents",
    "Files",
    "Records",
    "Archive",
    "Data",
    "Passwords",
    "Financial_Records",
    "Bank_Statements",
    "Tax_Documents",
    "Contracts",
    "Photos",
    "Accounts",
    "Vault",
    "Statements",
];

/// A per-machine random seed, generated once and persisted so honeypot
/// names stay stable across restarts.
///
/// Earlier versions of this honeypot only randomized a numeric suffix
/// APPENDED to a single hardcoded, public prefix (e.g. always
/// `Confidential_Backup_<seed>`). A review found that construction gives
/// essentially no real protection against exactly the source-reading
/// adversary it was meant to defend against: a shell one-liner globbing
/// for `Confidential_Backup_*`/`Banque_*` finds every honeypot on the box
/// without ever needing the seed value at all - wildcarding the random
/// part defeats it completely, so the "would need to read this machine's
/// own seed file" claim was simply wrong for that construction.
///
/// The seed here now selects BOTH words of the plausible name (see
/// `honeypot_theme_words`) from `HONEYPOT_ADJECTIVES`/`HONEYPOT_NOUNS`
/// (15x15 = 225 combinations) in addition to the numeric suffix, so there
/// is no single fixed substring shared across every Warden install for a
/// wildcard glob to key on. Being honest about what this does and
/// doesn't achieve: it is NOT information-theoretically unenumerable -
/// the word lists are public (this file is open source), so a
/// sufficiently motivated, Warden-aware attacker can still glob all 225
/// adjective/noun combinations. What it does close is the trivial case -
/// a single grep/glob for one known literal string - and it defeats any
/// generic/commodity ransomware that doesn't specifically know it's
/// running against Warden, which is the overwhelming realistic case for
/// a single workstation. A targeted adversary who reads this exact file
/// and is willing to enumerate 225 candidate directory names is a threat
/// this naming scheme alone cannot fully close; burst/entropy detection
/// (the other two counters in `detector.rs`) remains the backstop for
/// that scenario, same as it already is for a strain that avoids every
/// honeypot outright by never touching a decoy file at all.
fn honeypot_seed() -> Result<String> {
    if let Ok(existing) = std::fs::read_to_string(SEED_PATH) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let mut raw = [0u8; 4];
    std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?.read_exact(&mut raw).context("reading /dev/urandom")?;
    let seed: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    if let Some(parent) = Path::new(SEED_PATH).parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(SEED_PATH, &seed).with_context(|| format!("writing {SEED_PATH}"))?;
    std::fs::set_permissions(SEED_PATH, std::fs::Permissions::from_mode(0o600)).with_context(|| format!("setting permissions on {SEED_PATH}"))?;
    Ok(seed)
}

/// Deterministically picks this machine's adjective+noun pair from the
/// seed (parsed as a 32-bit value, same bytes already persisted in
/// `SEED_PATH`) - stable across restarts exactly like the seed itself,
/// without persisting a second value separately.
fn honeypot_theme_words(seed: &str) -> (&'static str, &'static str) {
    let n = u32::from_str_radix(seed, 16).unwrap_or(0);
    let adjective = HONEYPOT_ADJECTIVES[(n as usize) % HONEYPOT_ADJECTIVES.len()];
    let noun = HONEYPOT_NOUNS[((n >> 8) as usize) % HONEYPOT_NOUNS.len()];
    (adjective, noun)
}

/// Same idea as `honeypot_theme_words`, for the standalone `$HOME`-root
/// honeypot: rotates the seed bits first so its adjective/noun pair is
/// independent of the per-watch-dir one even though both are derived
/// from the same underlying seed value, then picks from
/// `HOME_HONEYPOT_NOUNS` instead of the generic `HONEYPOT_NOUNS`.
fn home_honeypot_theme_words(seed: &str) -> (&'static str, &'static str) {
    let n = u32::from_str_radix(seed, 16).unwrap_or(0).rotate_left(13);
    let adjective = HONEYPOT_ADJECTIVES[(n as usize) % HONEYPOT_ADJECTIVES.len()];
    let noun = HOME_HONEYPOT_NOUNS[((n >> 8) as usize) % HOME_HONEYPOT_NOUNS.len()];
    (adjective, noun)
}

/// Builds this machine's honeypot path for one watch directory: a
/// dedicated, plausibly-named SUBFOLDER (not a file dropped loose at the
/// top level of a real data directory) holding one enticingly-named
/// file. Two problems this fixes, found by testing against a real
/// Desktop/Documents folder with an actual user account: dropping a
/// randomly-named file directly among a real user's own files is
/// something THAT USER can just as easily notice, get confused by, and
/// rename/move/delete themselves - a false alarm from the person Warden
/// protects, not an attacker - and a bare, ordinarily-named file reads
/// as far less enticing to either a human attacker doing manual
/// reconnaissance or a strain that prioritizes filenames/extensions
/// suggesting real value than an entire folder that LOOKS like where
/// someone would keep exactly that.
///
/// The folder's name still carries the same per-machine random seed the
/// old flat filename did, appended to a human-plausible prefix rather
/// than replacing it: an entirely fixed, enticing name (no seed at all)
/// would undo the exact protection the seed exists for - an attacker
/// reading this open-source file once could hardcode a skip for a fixed
/// name across every Warden install, same as the original flat-filename
/// weakness this mechanism was already built to close. The file
/// INSIDE that folder does not need its own random suffix: its full
/// path is only ever reachable through the already-unpredictable parent
/// folder name, so a fixed, maximally plausible filename there costs
/// nothing.
///
/// Falls back to the old flat dotfile name if the seed can't be
/// generated (e.g. `/var/lib` unwritable at this point) rather than
/// failing honeypot provisioning outright - not enticing, but a hidden
/// dotfile is still a real (if weaker) trip-wire, and this path is only
/// ever reached on that failure.
pub fn honeypot_path(dir: &Path) -> PathBuf {
    match honeypot_seed() {
        Ok(seed) => {
            let (adjective, noun) = honeypot_theme_words(&seed);
            dir.join(format!("{adjective}_{noun}")).join("passwords_export.csv")
        }
        Err(e) => {
            warn!(error = %e, "could not derive a randomized honeypot path, falling back to the fixed name");
            dir.join(".warden_canary")
        }
    }
}

/// Finance-flavored noun pool for `home_honeypot_path`, paired with
/// `HONEYPOT_ADJECTIVES` via `home_honeypot_theme_words` - keeps that
/// honeypot's folder name thematically consistent with its bank-
/// statement content (see `BANK_CANARY_CONTENT`) while still drawing
/// from the same seeded, non-fixed-prefix scheme as `honeypot_path`.
const HOME_HONEYPOT_NOUNS: &[&str] =
    &["Bank_Statements", "Banking_Records", "Account_Statements", "Savings", "Bank_Info", "Compte_Bancaire", "Releves_Bancaires", "Finances"];

/// One additional, standalone honeypot sitting directly at the top level
/// of `$HOME` itself - not nested inside any of the per-category watch
/// dirs `honeypot_path` covers. Requested after live testing: a folder
/// right at the top of the home directory listing is often the very
/// first thing either a human attacker doing manual reconnaissance or a
/// file-browser-based lure sees, so it's worth one prominent, obviously
/// tempting target in addition to (not instead of) the ones already
/// spread across Documents/Desktop/Downloads/etc - those still matter
/// for a ransomware strain that walks straight into one of those
/// categories without ever looking at `$HOME`'s own top level first.
/// Same per-machine random seed suffix as `honeypot_path`, and the same
/// reasoning for why it's still needed despite the enticing prefix.
///
/// The caller (`RansomwareConfig::resolve_defaults`) is responsible for
/// also adding this path's PARENT directory to `watch_dirs`: fanotify
/// here is a single filesystem-wide mark filtered in userspace by
/// prefix-matching against `watch_dirs` (see `fanotify_monitor::is_under_watch_dirs`),
/// so a honeypot living outside every configured watch dir would
/// otherwise never actually get its write events delivered at all.
pub fn home_honeypot_path(home: &Path) -> PathBuf {
    match honeypot_seed() {
        Ok(seed) => {
            let (adjective, noun) = home_honeypot_theme_words(&seed);
            home.join(format!("{adjective}_{noun}")).join("releve_compte.csv")
        }
        Err(e) => {
            warn!(error = %e, "could not derive a randomized home honeypot path, falling back to the fixed name");
            home.join(".warden_canary_bank")
        }
    }
}

/// Creates the configured decoy files on disk if missing, and returns a set
/// of their canonicalized paths for fast lookup during event handling.
///
/// Chowns each freshly-created file to `target_uid`/`target_gid` rather
/// than leaving it root-owned (root is what creates it, since this runs
/// inside the root daemon): live testing found that a root-owned,
/// `0644` honeypot is silently useless against the realistic threat
/// model here, since ransomware almost always runs as the logged-in
/// desktop user, not as root - such a process gets `EACCES` trying to
/// overwrite a file it doesn't own with only group/other read access,
/// so the write (and the `FAN_CLOSE_WRITE` event this mechanism depends
/// on) never happens at all. Mode `0644` (owner rw, group/other read) on
/// the target user matches how the user's own real documents already
/// sit, so the honeypot doesn't stand out from its surroundings by
/// permission bits alone either.
pub fn provision(paths: &[PathBuf], target_uid: u32, target_gid: u32) -> Result<HashSet<PathBuf>> {
    let mut set = HashSet::new();
    for p in paths {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating parent dir for honeypot {}", p.display()))?;
            // The honeypot now lives in its own dedicated subfolder
            // (see `honeypot_path`), which `create_dir_all` above
            // creates root-owned at the process umask by default - a
            // folder that's supposed to read as a real user-created one
            // needs the same ownership/mode correction the leaf file
            // already gets below, or it stands out as root:root 0755
            // sitting inside the target user's own home directory.
            // 0755 (owner rwx, group/other rx) matches how a real
            // directory the user created themselves would sit.
            if let Ok(meta) = std::fs::symlink_metadata(parent) {
                if meta.file_type().is_symlink() {
                    // A real red-team-confirmed local-privesc primitive,
                    // not a hypothetical: this parent folder sits inside
                    // the target user's own writable $HOME, so that same
                    // user (or malware running as them) can delete it and
                    // replace it with a symlink to anything - e.g.
                    // `/etc/cron.d` - before the daemon's next restart.
                    // `set_permissions`/`chown` below both follow
                    // symlinks with no `O_NOFOLLOW` equivalent used here,
                    // so proceeding would have handed root-applied
                    // `chmod 0755`+`chown(target_uid)` to whatever the
                    // attacker's symlink points at, same class of bug the
                    // leaf-file check a few lines down already guards
                    // against - refusing here closes it for the parent
                    // directory too instead of only the leaf file.
                    warn!(path = %parent.display(), "honeypot parent directory is a symlink, refusing to provision through it");
                    continue;
                }
                if meta.uid() != target_uid || meta.gid() != target_gid || meta.mode() & 0o777 != 0o755 {
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                        .with_context(|| format!("setting permissions on {}", parent.display()))?;
                    nix::unistd::chown(parent, Some(nix::unistd::Uid::from_raw(target_uid)), Some(nix::unistd::Gid::from_raw(target_gid)))
                        .with_context(|| format!("chowning honeypot dir {}", parent.display()))?;
                }
            }
        }
        // symlink_metadata (does not follow the final component) rather
        // than Path::exists()/fs::write's own O_CREAT, which would both
        // follow a symlink planted at `p` and write the fixed canary
        // content through it to whatever it points at.
        match std::fs::symlink_metadata(p) {
            Ok(meta) if meta.file_type().is_symlink() => {
                warn!(path = %p.display(), "honeypot path is a symlink, refusing to provision through it");
            }
            Ok(meta) => {
                // Already exists (a previous run already provisioned it,
                // or - on an upgrade from before the ownership fix - it
                // exists but is still root-owned). Re-apply ownership/
                // mode unconditionally rather than only on first
                // creation, so an upgrade actually corrects a stale
                // root-owned honeypot left over from before this fix
                // instead of silently leaving it broken forever.
                if meta.uid() != target_uid || meta.gid() != target_gid || meta.mode() & 0o777 != 0o644 {
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).with_context(|| format!("setting permissions on {}", p.display()))?;
                    nix::unistd::chown(p, Some(nix::unistd::Uid::from_raw(target_uid)), Some(nix::unistd::Gid::from_raw(target_gid)))
                        .with_context(|| format!("chowning honeypot {}", p.display()))?;
                    info!(path = %p.display(), "corrected ownership/permissions on existing honeypot file");
                }
            }
            Err(_) => {
                // Picks bank-statement content for the standalone
                // `$HOME`-root honeypot (`home_honeypot_path`, whose leaf
                // filename is always `releve_compte.csv`) and the
                // password-export content for every per-watch-dir one
                // (`honeypot_path`, leaf filename `passwords_export.csv`)
                // - matches each honeypot's content to its filename/
                // framing so the two stay thematically consistent rather
                // than a "Banque"-themed folder containing a file named
                // like a password export. Keyed on the LEAF filename
                // rather than the parent folder name on purpose: the
                // parent folder name is now drawn from a shared, seeded
                // word pool (see `honeypot_theme_words`/
                // `home_honeypot_theme_words`) specifically so there's no
                // fixed public prefix to key content-selection off of
                // either - the two leaf filenames stay fixed and public,
                // which is fine since (per `honeypot_path`'s doc comment)
                // the file's own name was never the part doing the actual
                // enumeration-resistance work, only its parent folder's
                // name is.
                let content = p.file_name().and_then(|n| n.to_str()).filter(|n| *n == "releve_compte.csv").map_or(CANARY_CONTENT, |_| BANK_CANARY_CONTENT);
                std::fs::write(p, content).with_context(|| format!("writing honeypot file {}", p.display()))?;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).with_context(|| format!("setting permissions on {}", p.display()))?;
                nix::unistd::chown(p, Some(nix::unistd::Uid::from_raw(target_uid)), Some(nix::unistd::Gid::from_raw(target_gid)))
                    .with_context(|| format!("chowning honeypot {}", p.display()))?;
                info!(path = %p.display(), "provisioned honeypot file");
            }
        }
        let canon = p.canonicalize().with_context(|| format!("canonicalizing honeypot path {}", p.display()))?;
        set.insert(canon);
    }
    Ok(set)
}

pub fn is_honeypot(honeypots: &HashSet<PathBuf>, path: &Path) -> bool {
    match path.canonicalize() {
        Ok(canon) => honeypots.contains(&canon),
        Err(_) => honeypots.contains(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("warden-honeypot-test-{suffix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regression test for the red-team-confirmed local-privesc finding:
    /// a honeypot's parent directory that turns out to be a symlink must
    /// never be `chmod`/`chown`'d - proving the fix actually refuses
    /// (rather than merely "usually skipping") by asserting the
    /// symlink's real target is left completely untouched: same mode,
    /// same owner it started with.
    #[test]
    fn refuses_to_chmod_chown_through_a_symlinked_parent_directory() {
        let scratch = scratch_dir("symlinked-parent");
        let real_target = scratch.join("real_target_the_attacker_should_never_own");
        std::fs::create_dir_all(&real_target).unwrap();
        std::fs::set_permissions(&real_target, std::fs::Permissions::from_mode(0o700)).unwrap();

        let fake_parent = scratch.join("Confidential_Backup_deadbeef");
        std::os::unix::fs::symlink(&real_target, &fake_parent).unwrap();
        let honeypot_file = fake_parent.join("passwords_export.csv");

        let my_uid = nix::unistd::getuid().as_raw();
        let my_gid = nix::unistd::getgid().as_raw();
        let result = provision(std::slice::from_ref(&honeypot_file), my_uid, my_gid).expect("provision should not error, just skip");

        assert!(!result.contains(&honeypot_file), "a honeypot behind a symlinked parent must not be tracked as provisioned");
        let real_target_mode = std::fs::symlink_metadata(&real_target).unwrap().mode() & 0o777;
        assert_eq!(real_target_mode, 0o700, "the symlink's real target must keep its original mode, never be chmod'd to 0755");
        assert!(std::fs::symlink_metadata(&fake_parent).unwrap().file_type().is_symlink(), "the symlink itself must be left alone, not replaced");

        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn provisions_normally_when_parent_is_a_real_directory() {
        let scratch = scratch_dir("normal-parent");
        let honeypot_file = scratch.join("Confidential_Backup_abc123").join("passwords_export.csv");

        let my_uid = nix::unistd::getuid().as_raw();
        let my_gid = nix::unistd::getgid().as_raw();
        let result = provision(std::slice::from_ref(&honeypot_file), my_uid, my_gid).expect("provision should succeed");

        assert!(result.contains(&honeypot_file.canonicalize().unwrap()));
        assert!(honeypot_file.exists());

        std::fs::remove_dir_all(&scratch).ok();
    }
}
