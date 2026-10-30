/*
   claude-code-backdoor-check — YARA rules
   Trojanized anthropic.claude-code 2.1.313 (Cursor marketplace, 2026-10-29)

   Scan targets:
     ~/.cursor/extensions  ~/.vscode/extensions  (rule 1)
     ~/.config/            (rule 2)
     ~/Library/LaunchAgents  crontab dumps  Windows Tasks/Startup  (rule 3)
     ~/.ssh/authorized_keys  (rule 4)

   Example:  yara -r -s rules/yara/claude_code_backdoor.yar ~/.cursor/extensions ~/.config ~/.ssh

   https://github.com/happyhackingspace/claude-code-backdoor-check
*/

import "hash"

rule HHS_ClaudeCode_Backdoor_Loader
{
    meta:
        description = "Loader prepended to extension.js of trojanized anthropic.claude-code 2.1.313"
        author      = "HappyHackingSpace"
        date        = "2026-10-30"
        reference   = "https://opensourcemalware.com/blog/trojanized-claude-code-extension-plants-persistent-ssh-backdoor"
        severity    = "critical"
        hash        = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"

    strings:
        $c2      = "134.209.82.225" ascii wide
        $key     = "svc-telemetry" ascii wide
        $beacon  = ":8099/beacon" ascii wide
        $rfwd    = "*:0:localhost:22" ascii wide
        $tunnel  = "tunnel@" ascii wide
        $smtk    = ".smtk" ascii wide
        $label   = "com.apple.sysmond" ascii wide
        $task    = "SysMon" ascii wide fullword
        $rl      = "setremotelogin" ascii wide
        $win_ssh = "OpenSSH.Server" ascii wide
        $autossh = "autossh" ascii wide

    condition:
        filesize < 30MB and
        (
            hash.sha256(0, filesize) == "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15" or
            ($c2 and 2 of ($key, $beacon, $rfwd, $tunnel, $smtk, $label, $task, $rl, $win_ssh, $autossh)) or
            5 of ($key, $beacon, $rfwd, $tunnel, $smtk, $label, $task, $rl, $win_ssh, $autossh)
        )
}

rule HHS_ClaudeCode_Backdoor_TunnelScript
{
    meta:
        description = "Dropped reverse-tunnel script (~/.config/.smt, smt.cmd) of trojanized claude-code 2.1.313"
        author      = "HappyHackingSpace"
        date        = "2026-10-30"
        reference   = "https://cursor.com/blog/claude-code-extension-security-notice"
        severity    = "critical"

    strings:
        $c2     = "134.209.82.225" ascii wide
        $tunnel = "tunnel@" ascii wide
        $rfwd   = "localhost:22" ascii wide
        $r      = "-R" ascii wide
        $smtk   = ".smtk" ascii wide
        $smtk2  = "smtk" ascii wide fullword
        $nohost = "StrictHostKeyChecking=no" ascii wide nocase

    condition:
        filesize < 64KB and
        $rfwd and $r and
        ( $c2 or $tunnel ) and
        ( $smtk or $smtk2 or $nohost or $c2 )
}

rule HHS_ClaudeCode_Backdoor_Persistence
{
    meta:
        description = "Persistence entry (LaunchAgent / cron / scheduled task / Startup script) pointing at the dropped .smt script"
        author      = "HappyHackingSpace"
        date        = "2026-10-30"
        reference   = "https://opensourcemalware.com/blog/trojanized-claude-code-extension-plants-persistent-ssh-backdoor"
        severity    = "high"

    strings:
        $smt_unix = /\.config\/\.smt[^a-zA-Z0-9k]/ ascii
        $smt_win  = "smt.cmd" ascii wide nocase
        $label    = "com.apple.sysmond" ascii
        $plist    = "<plist" ascii
        $reboot   = "@reboot" ascii
        $task     = "SysMon" ascii wide fullword
        $c2       = "134.209.82.225" ascii wide

    condition:
        filesize < 256KB and
        (
            ($plist and $label and ($smt_unix or $c2)) or
            ($reboot and ($smt_unix or $c2)) or
            ($task and $smt_win) or
            ($smt_win and $c2)
        )
}

rule HHS_ClaudeCode_Backdoor_AuthorizedKey
{
    meta:
        description = "authorized_keys containing the svc-telemetry key planted by trojanized claude-code 2.1.313"
        author      = "HappyHackingSpace"
        date        = "2026-10-30"
        reference   = "https://cursor.com/blog/claude-code-extension-security-notice"
        severity    = "critical"
        fingerprint = "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"

    strings:
        $comment = / svc-telemetry(\r?\n|$)/ ascii
        $type    = "ssh-ed25519 " ascii

    condition:
        filesize < 1MB and $type and $comment
}
