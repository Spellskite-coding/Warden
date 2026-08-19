use std::collections::HashSet;
use std::path::Path;

/// Reads a text file as lines. `None` if it doesn't exist or isn't valid
/// UTF-8 text (binary files aren't meaningful to line-diff, and none of
/// the targets this module watches are expected to be binary).
pub fn read_lines(path: &Path) -> Option<Vec<String>> {
    std::fs::read_to_string(path).ok().map(|s| s.lines().map(str::to_string).collect())
}

/// Lines present in `new` but not in `old` - a simple set difference, not a
/// positional diff. That means reordering existing lines never gets
/// flagged (acceptable: reordering an existing `alias` isn't a persistence
/// concern) and a line removed then later re-added identically won't
/// re-trigger either. Good enough for "what new content showed up", which
/// is what actually matters here.
pub fn added_lines(old: &[String], new: &[String]) -> Vec<String> {
    let old_set: HashSet<&str> = old.iter().map(String::as_str).collect();
    new.iter().filter(|l| !old_set.contains(l.as_str())).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_appended_line() {
        let old = vec!["a".to_string(), "b".to_string()];
        let new = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(added_lines(&old, &new), vec!["c".to_string()]);
    }

    #[test]
    fn reordering_is_not_flagged() {
        let old = vec!["a".to_string(), "b".to_string()];
        let new = vec!["b".to_string(), "a".to_string()];
        assert!(added_lines(&old, &new).is_empty());
    }

    #[test]
    fn brand_new_file_flags_every_line() {
        let old: Vec<String> = vec![];
        let new = vec!["x".to_string(), "y".to_string()];
        assert_eq!(added_lines(&old, &new), new);
    }
}
