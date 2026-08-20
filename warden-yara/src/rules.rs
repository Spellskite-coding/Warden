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
            let entries = std::fs::read_dir(dir).with_context(|| format!("reading custom rules dir {}", dir.display()))?;
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
