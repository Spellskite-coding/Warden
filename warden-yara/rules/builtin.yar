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
    strings:
        $tcp = "/dev/tcp/" ascii
        $udp = "/dev/udp/" ascii
        $exec = "exec " ascii
    condition:
        ($tcp or $udp) and $exec
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
