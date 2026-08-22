rule Eicar_Test_File
{
    meta:
        description = "The EICAR antivirus test file - a standard, harmless string every AV/EDR vendor uses to verify on-access detection actually works"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule Bash_Dev_Tcp_Reverse_Shell
{
    meta:
        description = "Bash /dev/tcp or /dev/udp reverse shell pattern combined with exec"
        severity = "high"
        // A plain, unmodified `/bin/bash` binary itself contains the bare
        // literal string "/dev/tcp/" (used internally to implement its own
        // /dev/tcp redirection feature) alongside "exec " somewhere in its
        // compiled strings table - confirmed live: copying stock
        // /usr/bin/bash into a watched directory matched this rule and got
        // quarantined as a "reverse shell", a real false positive against
        // one of the most common legitimate binaries on any Linux system.
        // Two changes close that without weakening real detection: the
        // redirection-operator regex only matches actual shell REDIRECTION
        // SYNTAX (">/dev/tcp/host/port", "3<>/dev/tcp/..."), which the bare
        // path string inside bash's own binary doesn't happen to be
        // adjacent to; and both trigger strings must appear within the
        // first 64KB of the file, which any real reverse-shell payload
        // (always a small text script, from a one-liner up to a few KB)
        // does trivially.
        //
        // This used to be a plain `filesize < 65536` condition gating the
        // *entire* file instead - found, in a later review, to be a real
        // bypass: an attacker can keep the actual payload unchanged (still
        // a working reverse shell) and just pad the file past 64KB with
        // trailing junk (a comment block, here-doc, or anything bash never
        // reaches), pushing `filesize` over the cutoff and making YARA
        // skip scanning the file's content at all. Bounding *where* the
        // matched strings must occur - rather than exempting the whole
        // file once it crosses a size threshold - still lets a script grow
        // arbitrarily large after the payload without evading detection.
    strings:
        $tcp_redir = /[<>]&?\s{0,2}\/dev\/tcp\// ascii
        $udp_redir = /[<>]&?\s{0,2}\/dev\/udp\// ascii
        $exec = "exec " ascii
    condition:
        (($tcp_redir in (0..65536)) or ($udp_redir in (0..65536))) and ($exec in (0..65536))
}

rule Netcat_Reverse_Shell
{
    meta:
        description = "netcat invoked with -e/-c to bind a shell to a socket"
        severity = "high"
    strings:
        $a = "nc -e" ascii
        $b = "ncat -e" ascii
        $c = "nc.traditional -e" ascii
        $d = /nc(\.traditional)?\s+-[a-zA-Z]*e[a-zA-Z]*\s/ ascii
    condition:
        any of them
}

rule Python_Reverse_Shell
{
    meta:
        description = "Common Python reverse shell one-liner pattern (socket + dup2 + pty/exec)"
        severity = "high"
    strings:
        $socket = "socket.socket" ascii
        $dup2 = "dup2" ascii
        $spawn = "pty.spawn" ascii
        $exec_family = /os\.(system|execve)/ ascii
    condition:
        $socket and $dup2 and ($spawn or $exec_family)
}

rule Php_Webshell_Obfuscated
{
    meta:
        description = "PHP webshell pattern: eval/system/exec fed by base64/gzinflate-decoded request input"
        severity = "critical"
    strings:
        $eval = "eval(" ascii
        $sys = /\b(system|exec|shell_exec|passthru)\s*\(/ ascii
        $decode = /base64_decode|gzinflate|str_rot13/ ascii
        $input = /\$_(POST|GET|REQUEST|COOKIE)/ ascii
    condition:
        ($eval or $sys) and $decode and $input
}

rule Base64_Piped_To_Shell
{
    meta:
        description = "base64-decoded content piped directly into a shell interpreter"
        severity = "high"
    strings:
        $a = /base64\s+(-d|--decode)[^\n]{0,40}\|\s*(ba)?sh\b/ ascii
        $b = /echo\s+[A-Za-z0-9+\/=]{20,}\s*\|\s*base64\s+(-d|--decode)/ ascii
    condition:
        any of them
}
