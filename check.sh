#!/usr/bin/env bash
#
# claude-code-backdoor-check
# Read-only IOC scanner for the trojanized "anthropic.claude-code" 2.1.313
# editor extension (Cursor marketplace, Oct 29 2026).
#
#   - Never modifies, deletes or uploads anything.
#   - No sudo, no network access, no external dependencies.
#   - macOS (bash 3.2+) and Linux, same checks on both.
#
# Exit codes: 0 = clean, 1 = indicators found, 2 = usage error
#
# https://github.com/happyhackingspace/claude-code-backdoor-check

set -u

VERSION="1.1.0"

# ---- Indicators of compromise -------------------------------------------------
C2_IP="134.209.82.225"
C2_RE="134\.209\.82\.225"
C2_SHOW="134.209.82[.]225"        # defanged, for display only
BAD_VERSION="2.1.313"
BAD_VERSION_RE="2\.1\.313"
KEY_COMMENT="svc-telemetry"
KEY_FP="SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
KEY_FP_SHORT="0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
BAD_EXTJS_SHA256="ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
LAUNCH_LABEL="com.apple.sysmond"      # reuses the name of a real Apple *system* daemon
EXPOSURE_START="2026-10-29"           # 02:27 PT = 09:27 UTC
EXPOSURE_EPOCH=1793266020

# Generic "this file references the implant" pattern (persistence, rc files, units).
# Matches ~/.config/.smt, .smtk, smt.cmd — but not unrelated words like ".smtp".
IOC_RE="$C2_RE|svc-telemetry|tunnel@|\.config/\.?smtk?([^a-zA-Z0-9]|\$)|smt\.cmd"
# Loader signatures inside extension.js
LOADER_RE="$C2_RE|svc-telemetry|:8099/beacon|\*:0:localhost:22"

# ---- Args / colors ------------------------------------------------------------
USE_COLOR=1
DEEP=0
[ -t 1 ] || USE_COLOR=0
[ -n "${NO_COLOR:-}" ] && USE_COLOR=0

usage() {
  cat <<EOF
Usage: $0 [--deep] [--no-color] [--version] [--help]

Read-only check for the trojanized anthropic.claude-code $BAD_VERSION extension.

  --deep       also search sshd logs for logins through the reverse tunnel
               (macOS: 'log show' can take a few minutes)
  --no-color   plain output (NO_COLOR is honoured too)

Exit codes: 0 = clean, 1 = indicators found, 2 = usage error
EOF
}

for arg in "$@"; do
  case "$arg" in
    --deep)       DEEP=1 ;;
    --no-color)   USE_COLOR=0 ;;
    -v|--version) echo "claude-code-backdoor-check $VERSION"; exit 0 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

if [ "$USE_COLOR" -eq 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; C=""; B=""; D=""; N=""
fi

HIGH=0; MED=0; INFO=0
STEP=0; TOTAL=9

section() { STEP=$((STEP+1)); printf "\n${B}${C}[%d/%d]${N} ${B}%s${N}\n" "$STEP" "$TOTAL" "$1"; }
ok()      { printf "  ${G}✔${N} %s\n" "$1"; }
high()    { printf "  ${R}${B}✖ HIGH${N}  %s\n" "$1"; HIGH=$((HIGH+1)); }
med()     { printf "  ${Y}${B}! MED${N}   %s\n" "$1"; MED=$((MED+1)); }
info()    { printf "  ${C}i INFO${N}  %s\n" "$1"; INFO=$((INFO+1)); }
detail()  {  # defang the C2, shorten $HOME, trim trailing space
  printf "          ${D}%s${N}\n" "$(printf '%s' "$1" | sed -e "s|$C2_RE|$C2_SHOW|g" -e "s|$HOME|~|g" -e 's/[[:space:]]*$//')"
}
skip()    { printf "  ${D}- %s${N}\n" "$1"; }
short()   { echo "$1" | sed "s|^$HOME|~|"; }
count()   { echo $((HIGH + MED)); }

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

mtime() {  # epoch mtime, portable
  # GNU first: on Linux 'stat -f' silently means "filesystem status".
  t="$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null)"
  case "$t" in ''|*[!0-9]*) echo 0 ;; *) echo "$t" ;; esac
}

OS="$(uname -s)"
case "$OS" in
  Darwin) APPDATA="$HOME/Library/Application Support" ;;
  Linux)  APPDATA="${XDG_CONFIG_HOME:-$HOME/.config}" ;;
  *) echo "Unsupported OS: $OS (macOS and Linux only)" >&2; exit 2 ;;
esac

EXT_DIRS="$HOME/.cursor/extensions
$HOME/.cursor-server/extensions
$HOME/.vscode/extensions
$HOME/.vscode-insiders/extensions
$HOME/.vscode-server/extensions
$HOME/.vscode-oss/extensions
$HOME/.windsurf/extensions
$HOME/.windsurf-server/extensions"

EDITORS="Cursor
Code
Code - Insiders
VSCodium
Windsurf"

# ---- Header -------------------------------------------------------------------
printf "${B}claude-code-backdoor-check${N} ${D}v%s${N}\n" "$VERSION"
printf "${D}target  anthropic.claude-code %s · C2 %s · read-only${N}\n" "$BAD_VERSION" "$C2_SHOW"
printf "${D}host    %s · %s · %s %s%s${N}\n" "$(hostname)" "$(id -un)" "$OS" "$(uname -m)" \
  "$([ $DEEP -eq 1 ] && echo ' · deep')"

# ==============================================================================
section "Installed extensions"
# ==============================================================================
found_any=0
while IFS= read -r d; do
  [ -d "$d" ] || continue
  for e in "$d"/anthropic.claude-code-*; do
    [ -d "$e" ] || continue
    found_any=1
    name="$(basename "$e")"
    case "$name" in
      *"-$BAD_VERSION"*) high "Malicious version installed: $(short "$e")" ;;
      *)                 ok   "$name  ${D}$(short "$d")${N}" ;;
    esac
    js="$e/extension.js"
    [ -f "$js" ] || js="$e/dist/extension.js"
    if [ -f "$js" ]; then
      [ "$(sha256 "$js")" = "$BAD_EXTJS_SHA256" ] && high "Known-bad extension.js hash: $(short "$js")"
      sig="$(grep -oE "$LOADER_RE" "$js" 2>/dev/null | sort -u | tr '\n' ' ')"
      [ -n "$sig" ] && { high "Loader signatures in $(short "$js")"; detail "$sig"; }
    fi
  done
done <<EOF
$EXT_DIRS
EOF
[ "$found_any" -eq 0 ] && ok "No Claude Code extension installed"

# ==============================================================================
section "Install history (was $BAD_VERSION ever present?)"
# ==============================================================================
# Auto-update to 2.1.314 removes the bad build but NOT what it planted.
s=$(count)
while IFS= read -r d; do
  for f in "$d/extensions.json" "$d/.obsolete"; do
    # matches "relativeLocation":"anthropic.claude-code-2.1.313-…" and
    # {"id":"anthropic.claude-code",…},"version":"2.1.313"
    [ -f "$f" ] && grep -qE "anthropic\.claude-code-$BAD_VERSION_RE|anthropic\.claude-code\"[^{]{0,200}\"version\": ?\"$BAD_VERSION_RE\"" "$f" 2>/dev/null \
      && med "$BAD_VERSION recorded in $(short "$f")"
  done
done <<EOF
$EXT_DIRS
EOF
while IFS= read -r ed; do
  base="$APPDATA/$ed"
  [ -d "$base" ] || continue
  for v in "$base"/CachedExtensionVSIXs/anthropic.claude-code-"$BAD_VERSION"*; do
    [ -e "$v" ] && med "Cached VSIX: $(short "$v")"
  done
  if [ -d "$base/logs" ]; then
    lg="$(grep -rlsE "anthropic\.claude-code.{0,40}$BAD_VERSION_RE" "$base/logs" 2>/dev/null | head -3)"
    if [ -n "$lg" ]; then
      med "$ed logs mention $BAD_VERSION"
      echo "$lg" | while IFS= read -r l; do detail "$(short "$l")"; done
    fi
  fi
done <<EOF
$EDITORS
EOF
[ "$(count)" -eq "$s" ] && ok "No trace of $BAD_VERSION in extension metadata, VSIX cache or editor logs"

# ==============================================================================
section "SSH keys"
# ==============================================================================
s=$(count)
for ak in "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys2"; do
  [ -f "$ak" ] || continue
  if grep -q "$KEY_COMMENT" "$ak"; then
    high "Attacker key ($KEY_COMMENT) in $(short "$ak")"
    detail "line $(grep -n "$KEY_COMMENT" "$ak" | cut -d: -f1 | tr '\n' ' ')"
  fi
  ssh-keygen -lf "$ak" 2>/dev/null | grep -qF "$KEY_FP" \
    && high "Attacker key fingerprint matched in $(short "$ak")"
  if [ "$(mtime "$ak")" -ge "$EXPOSURE_EPOCH" ] && [ "$(count)" -eq "$s" ]; then
    info "$(short "$ak") was modified after $EXPOSURE_START — review it"
  fi
done
[ "$(count)" -eq "$s" ] && ok "No attacker key in authorized_keys"

# ==============================================================================
section "Dropped files"
# ==============================================================================
s=$(count)
for f in "$HOME/.config/.smt" "$HOME/.config/.smtk" "$HOME/.config/smt.cmd" "$HOME/.config/smtk"; do
  [ -e "$f" ] && high "Present: $(short "$f")"
done
tmpdirs="${TMPDIR:-/tmp}"; tmpdirs="${tmpdirs%/}"
for t in /tmp /var/tmp; do [ "$tmpdirs" != "$t" ] && tmpdirs="$tmpdirs $t"; done
for t in $tmpdirs; do
  for f in "$t"/.stk_*; do
    [ -e "$f" ] && med "Temp artifact: $(short "$f")"
  done
done
[ "$(count)" -eq "$s" ] && ok "No dropped files"

# ==============================================================================
section "Persistence"
# ==============================================================================
s=$(count)
scan_paths() {  # $1 = label, rest = files/dirs; flags any that reference the implant
  label="$1"; shift
  for p in "$@"; do
    [ -e "$p" ] || continue
    grep -rlsE "$IOC_RE" "$p" 2>/dev/null | while IFS= read -r m; do
      printf "%s\t%s\n" "$label" "$m"
    done
  done
}
hits=""
if [ "$OS" = "Darwin" ]; then
  plist="$HOME/Library/LaunchAgents/$LAUNCH_LABEL.plist"
  [ -e "$plist" ] && high "User LaunchAgent: $(short "$plist")"
  launchctl print "gui/$(id -u)/$LAUNCH_LABEL" >/dev/null 2>&1 \
    && high "$LAUNCH_LABEL is loaded in your user (gui) launchd domain"
  hits="$(scan_paths "LaunchAgent/Daemon" "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons)"
else
  hits="$(scan_paths "systemd unit" "$HOME/.config/systemd/user" /etc/systemd/system /etc/systemd/user)
$(scan_paths "XDG autostart" "$HOME/.config/autostart" /etc/xdg/autostart)
$(scan_paths "system cron" /etc/crontab /etc/cron.d /etc/rc.local)"
fi
hits="$hits
$(scan_paths "shell startup" "$HOME/.profile" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.bash_login" \
  "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.config/fish/config.fish")"
echo "$hits" | while IFS="$(printf '\t')" read -r label m; do
  [ -n "${m:-}" ] || continue
  [ "$m" = "${plist:-}" ] && continue
  printf "%s\n" "$label|$m"
done > "${TMPDIR:-/tmp}/.ioc_persist.$$"
while IFS='|' read -r label m; do
  high "$label references implant: $(short "$m")"
done < "${TMPDIR:-/tmp}/.ioc_persist.$$"
rm -f "${TMPDIR:-/tmp}/.ioc_persist.$$"

cron="$(crontab -l 2>/dev/null || true)"
if echo "$cron" | grep -qE "$IOC_RE"; then
  high "User crontab references implant"
  echo "$cron" | grep -E "$IOC_RE" | while IFS= read -r l; do detail "$l"; done
fi
[ "$(count)" -eq "$s" ] && ok "No persistence (launchd/systemd/cron/autostart/shell rc)"

# ==============================================================================
section "Running processes"
# ==============================================================================
s=$(count)
procs="$(ps ax -o pid=,ppid=,command= 2>/dev/null)"
# Only ssh/autossh binaries with the implant's tunnel arguments ...
tun="$(echo "$procs" \
  | grep -E -- "^ *[0-9]+ +[0-9]+ +([^ ]*/)?(auto)?ssh " \
  | grep -E -- "$C2_RE|tunnel@|-R '?\*:0:localhost:22|autossh -M 0" || true)"
# ... and shells running the dropped script.
# The dropped script must be what the shell is executing, not just mentioned in argv.
drv="$(echo "$procs" \
  | grep -E -- "^ *[0-9]+ +[0-9]+ +([^ ]*/)?(ba|z|da|k)?sh +(-[a-zA-Z]+ +)?[^ ]*\.config/\.?smt( |\$)" || true)"
if [ -n "$tun" ]; then
  high "Reverse SSH tunnel running"
  echo "$tun" | while IFS= read -r l; do detail "$(echo "$l" | awk '{p=$1; pp=$2; $1=$2=""; sub(/^ +/,""); printf "pid %s (ppid %s)  %s", p, pp, $0}' | cut -c1-140)"; done
fi
if [ -n "$drv" ]; then
  high "Dropped script is running"
  echo "$drv" | while IFS= read -r l; do detail "$(echo "$l" | awk '{p=$1; pp=$2; $1=$2=""; sub(/^ +/,""); printf "pid %s (ppid %s)  %s", p, pp, $0}' | cut -c1-140)"; done
fi
[ "$(count)" -eq "$s" ] && ok "No tunnel or implant process"

# ==============================================================================
section "Network & SSH trust"
# ==============================================================================
s=$(count)
conns=""
if command -v lsof >/dev/null 2>&1; then
  conns="$(lsof -nP -i "@$C2_IP" 2>/dev/null | tail -n +2 || true)"
elif command -v ss >/dev/null 2>&1; then
  conns="$(ss -tnp 2>/dev/null | grep -F "$C2_IP" || true)"
fi
if [ -n "$conns" ]; then
  high "Active connection to $C2_SHOW"
  echo "$conns" | while IFS= read -r l; do detail "$(echo "$l" | cut -c1-140)"; done
fi
for kh in "$HOME/.ssh/known_hosts" "$HOME/.ssh/known_hosts2"; do
  [ -f "$kh" ] || continue
  if ssh-keygen -F "$C2_IP" -f "$kh" >/dev/null 2>&1 || grep -qF "$C2_IP" "$kh"; then
    high "$C2_SHOW is in $(short "$kh") — the tunnel connected at least once"
  fi
done
[ "$(count)" -eq "$s" ] && ok "No connection to C2 and no C2 host key on record"

# ==============================================================================
section "SSH server"
# ==============================================================================
s=$(count)
listening=0
if [ "$OS" = "Darwin" ]; then
  netstat -an -p tcp 2>/dev/null | grep -qE '[.:]22 .*LISTEN' && listening=1
else
  { ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null; } | grep -qE '[.:]22[[:space:]]' && listening=1
fi
if [ "$listening" -eq 1 ]; then
  info "sshd is listening on :22 — if you didn't enable it, the implant may have"
  if [ "$OS" = "Darwin" ]; then detail "verify:  sudo systemsetup -getremotelogin"
  else detail "verify:  systemctl status ssh sshd"; fi
else
  ok "No SSH server listening on :22"
fi

if [ "$DEEP" -eq 1 ]; then
  # Logins through the reverse tunnel reach the local sshd from 127.0.0.1 / ::1,
  # authenticated with the attacker's key.
  logs=""
  if [ "$OS" = "Darwin" ]; then
    printf "  ${D}… reading unified log since %s (can take a few minutes)${N}\n" "$EXPOSURE_START"
    logs="$(log show --style syslog --start "$EXPOSURE_START 00:00:00" \
             --predicate 'process == "sshd" OR process == "sshd-session"' 2>/dev/null)"
  else
    logs="$(journalctl -u ssh -u sshd --since "$EXPOSURE_START" --no-pager -q 2>/dev/null)"
    for f in /var/log/auth.log /var/log/secure; do
      [ -r "$f" ] && logs="$logs
$(cat "$f")"
    done
  fi
  if [ -z "$logs" ]; then
    skip "sshd logs not readable as this user (Linux: add yourself to 'adm'/'systemd-journal' or run with sudo)"
  else
    k="$(echo "$logs" | grep -F "$KEY_FP_SHORT" | grep -i "accepted" || true)"
    l="$(echo "$logs" | grep -iE "accepted .* from (127\.0\.0\.1|::1)" || true)"
    if [ -n "$k" ]; then
      high "sshd accepted the ATTACKER KEY — someone logged in through the tunnel"
      echo "$k" | head -5 | while IFS= read -r x; do detail "$(echo "$x" | cut -c1-140)"; done
    elif [ -n "$l" ]; then
      med "sshd accepted localhost logins since $EXPOSURE_START (tunnel logins look like this)"
      echo "$l" | head -5 | while IFS= read -r x; do detail "$(echo "$x" | cut -c1-140)"; done
    else
      ok "No suspicious sshd logins since $EXPOSURE_START"
    fi
  fi
else
  skip "sshd login history not checked (use --deep)"
fi

# ==============================================================================
section "Exposure (what to rotate if compromised)"
# ==============================================================================
# Names only — values are never read or printed.
envnames="$(env | cut -d= -f1 | grep -E 'KEY|TOKEN|SECRET|PASS|AWS|GCP' | sort -u | head -40 | tr '\n' ' ')"
if [ -n "$envnames" ]; then
  printf "  ${D}env var names the implant would have sent (this shell; values not read):${N}\n"
  detail "$envnames"
fi
creds=""
for f in .ssh/id_rsa .ssh/id_ed25519 .ssh/id_ecdsa .aws/credentials .config/gcloud \
         .azure .kube/config .docker/config.json .npmrc .pypirc .netrc \
         .config/gh/hosts.yml .git-credentials .config/doctl; do
  [ -e "$HOME/$f" ] && creds="${creds:+$creds  }~/$f"
done
if [ -n "$creds" ]; then
  printf "  ${D}credential files readable by your user (contents not read):${N}\n"
  detail "$creds"
fi
[ -z "$envnames$creds" ] && ok "No obvious credential env vars or files"

# ---- Summary ------------------------------------------------------------------
echo
LINE="──────────────────────────────────────────────────────────────"
printf "${D}%s${N}\n" "$LINE"
if [ $HIGH -gt 0 ]; then
  printf " ${R}${B}✖ COMPROMISED${N}   high %d · medium %d · info %d\n\n" "$HIGH" "$MED" "$INFO"
  echo "   1. Disconnect this machine from the network."
  echo "   2. Collect evidence BEFORE deleting anything."
  echo "   3. Follow README → \"If you get a hit\"."
  echo "   4. Rotate the credentials above from a different, clean machine."
  RC=1
elif [ $MED -gt 0 ]; then
  printf " ${Y}${B}! EXPOSED${N}   high %d · medium %d · info %d\n\n" "$HIGH" "$MED" "$INFO"
  echo "   $BAD_VERSION was on this machine, but no active implant artifact was found."
  echo "   Re-run with --deep, then see README → \"Exposed but clean?\"."
  RC=1
else
  printf " ${G}${B}✔ CLEAN${N}   no indicators · info %d\n\n" "$INFO"
  echo "   Keep the extension at 2.1.314+ and block $C2_SHOW outbound."
  RC=0
fi
printf "${D}%s${N}\n" "$LINE"
exit $RC
