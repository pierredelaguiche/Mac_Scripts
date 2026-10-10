#!/bin/bash
# ============================================================
# mac_audit.sh — Security, Non-Factory Modification & Disk Audit for macOS
#
# Run (report only, nothing touched):   bash scripts/mac_audit.sh
# Move flagged junk to quarantine:       bash scripts/mac_audit.sh --quarantine
# Permanently empty the quarantine:      bash scripts/mac_audit.sh --purge-quarantine
#
# OUTPUT
#   - Terminal (colored) + plain-text report: ~/.mac_audit/reports/audit_<ts>.txt
#   - Markdown report: <repo>/outputs/mac_audit_<ts>.md  (falls back to
#     ~/.mac_audit/reports/ if the script isn't inside the repo layout)
#   - Machine-readable inventory: ~/.mac_audit/inventory.json (+ copy in
#     <repo>/outputs/ for the weekly Claude maintenance task)
#
# SCOPE — "non-factory modifications"
#   [1] security posture (+ sealed root, XProtect, update config, auto-login)
#   [2] software inventory (+ pkg receipts)
#   [3] unused apps             [4] local AI tools (CVE checks)
#   [5] suspicious artifacts (home, ~/Library hidden entries, /Users/Shared,
#       executables staged in tmp dirs)
#   [6] data collectors
#   [7] TCC permissions (user AND system TCC.db)
#   [8] LaunchAgents/Daemons (+ malware IOCs, program signature, missing
#       binaries, root-run programs writable by non-root = privesc)
#   [9] other persistence (login items, BTM, cron, at, hooks, periodic,
#       authorization plugins, legacy startup)
#   [10] system modifications (/etc, system-wide shell files, PATH, sudoers,
#        kexts, system extensions, profiles, root CAs, shell rc files)
#   [11] root & privilege surface (/ top level, SUID/SGID, privileged helper
#        tools, world-writable system paths, /var/root)
#   [12] user accounts & home (UID-0 clones, shell-bearing system accounts,
#        guest/auto-login, remote logins, SSH keys, credential files,
#        home permissions, files in home not owned by you)
#   [13] app extensions & plug-ins (pluginkit, browser extensions,
#        QuickLook/Spotlight/PreferencePanes/Frameworks/etc.)
#   [14] Library leftovers (orphaned Containers / Saved State / prefs of
#        uninstalled apps)
#   [15] network configuration (proxies, DNS, VPN, remote access services,
#        firewall allow-list)
#   [16] outbound connections   [17] disk usage (+ ~/Library, /Library,
#        dev caches, snapshots, files >1 GB)   [18] summary
#
# PRIVILEGE LEVELS
#   Plain run: everything a normal user can see. Recommended.
#   sudo run (sudo bash scripts/mac_audit.sh): adds root-only checks —
#     sfltool dumpbtm, /var/root, all users' crontabs/LaunchAgents/SSH keys,
#     sudoers NOPASSWD rules, system-level profiles. User-context commands
#     (brew, login items, crontab, trust settings) still run as the invoking
#     user via sudo -u; reports are chowned back to that user.
#     --quarantine is refused under sudo (it must never move files as root).
#   Full Disk Access for Terminal: unlocks TCC databases and Library sizes.
#
# SAFETY MODEL
#   - Default run is 100% read-only. No file is ever moved or deleted.
#   - --quarantine MOVES (never deletes) flagged items into
#     ~/.mac_audit/quarantine/<timestamp>/ after you type a confirmation.
#     Nothing leaves your disk.
#   - --purge-quarantine is the ONLY mode that deletes anything, and it
#     only deletes what's already sitting in the quarantine folder, after
#     a second explicit "PURGE" confirmation. This is the easy-delete path.
#   - Anything owned by root, or anything this script isn't certain about,
#     is reported for manual review and is NEVER auto-flagged for removal.
#   - Non-factory modifications are REPORTED, never reverted. Plenty of
#     them are deliberate (Touch ID sudo, dev entries in /etc/hosts) —
#     the report exists so you can vouch for each one, not so the script
#     can undo them.
#
# PORTABILITY
#   Written for the stock /bin/bash (3.2) on macOS: no associative arrays,
#   no sort -V, no GNU-only flags. BSD stat/date/sed throughout.
# ============================================================

set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ESC=$(printf '\033')

# ---------- privilege context ----------
# Under sudo, $HOME may be /var/root (macOS sudo does not always keep HOME).
# Resolve the invoking user's real home so every user-domain check still
# audits that user, not root.
IS_ROOT=false
[ "$(id -u)" -eq 0 ] && IS_ROOT=true
TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$IS_ROOT" = true ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  _TH=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  [ -n "$_TH" ] && [ -d "$_TH" ] && HOME="$_TH"
fi
# Run a command as the audited user (no-op when not under sudo).
as_user() {
  if [ "$IS_ROOT" = true ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    sudo -u "$SUDO_USER" -H "$@"
  else
    "$@"
  fi
}

AUDIT_DIR="$HOME/.mac_audit"
QUARANTINE_DIR="$AUDIT_DIR/quarantine"
TS="$(date +%Y-%m-%d_%H%M%S)"
REPORT="$AUDIT_DIR/reports/audit_$TS.txt"
INVENTORY="$AUDIT_DIR/inventory.json"
mkdir -p "$AUDIT_DIR/reports" "$QUARANTINE_DIR"

# Markdown report goes to the repo's outputs/ folder when the script lives
# in the repo (…/scripts/mac_audit.sh with a sibling outputs/); otherwise
# falls back to the state dir. Nothing else depends on the repo layout.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
if [ -d "$REPO_ROOT/outputs" ]; then
  OUT_DIR="$REPO_ROOT/outputs"
else
  OUT_DIR="$AUDIT_DIR/reports"
fi
MD_REPORT="$OUT_DIR/mac_audit_$TS.md"

REVIEW_ONLY=()      # flagged but never auto-removable (root-owned, unclear, security-relevant)
SAFE_CANDIDATES=()  # known junk/cache/legacy artifacts — quarantine-eligible
NONFACTORY=()       # non-factory modifications, informational (deliberate mods land here)

# ---------- output helpers ----------
# Three channels: terminal (colored), txt report (colored, greppable with
# less -R), markdown report (ANSI-stripped, sections fenced for alignment).
MD_FENCE_OPEN=false
md()  { printf '%s\n' "$1" >> "$MD_REPORT"; }
md_open_fence()  { if [ "$MD_FENCE_OPEN" = false ]; then md '```text'; MD_FENCE_OPEN=true; fi; }
md_close_fence() { if [ "$MD_FENCE_OPEN" = true ];  then md '```'; MD_FENCE_OPEN=false; fi; }

# logt: terminal + txt only (dividers, headers — markdown has its own headings)
logt() { echo -e "$1" | tee -a "$REPORT"; }
# log: terminal + txt + markdown (body content)
log() {
  echo -e "$1" | tee -a "$REPORT"
  md_open_fence
  echo -e "$1" | sed "s/${ESC}\[[0-9;]*m//g" >> "$MD_REPORT"
}
divider() { logt "\n${CYAN}══════════════════════════════════════════════════${RESET}"; }

SECTION_NUM=0
section() {
  SECTION_NUM=$((SECTION_NUM + 1))
  divider
  logt "\n${BOLD}[ $SECTION_NUM ] $1${RESET}"
  md_close_fence
  md ""
  md "## $SECTION_NUM. $1"
  md ""
  # Open the fence HERE, in the parent shell. Many log() calls run inside
  # `cmd | while` subshells; if the first log of a section ran in one, the
  # fence was opened in the file but MD_FENCE_OPEN stayed false in the parent,
  # so the next section() never closed it and the headings rendered as code.
  [ "${2:-}" = "nofence" ] || md_open_fence
}

json_escape() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
note_mod() { NONFACTORY+=("$1"); }

# ---------- inspection helpers ----------
# Signature summary for a binary/bundle: "signed: <first Authority>",
# "ad-hoc", "UNSIGNED", or "MISSING".
sig_status() {
  local f="$1" info auth
  [ -e "$f" ] || { echo "MISSING"; return; }
  info=$(codesign -dv --verbose=2 "$f" 2>&1)
  if echo "$info" | grep -q "not signed at all"; then echo "UNSIGNED"; return; fi
  if echo "$info" | grep -q "Signature=adhoc"; then echo "ad-hoc"; return; fi
  auth=$(echo "$info" | sed -n 's/^Authority=//p' | head -1)
  if [ -n "$auth" ]; then echo "signed: $auth"; else echo "UNSIGNED"; fi
}
# Shell-startup red flags: pipe-a-download-to-shell, base64-decoded eval,
# dylib injection. Shared by every rc-file scan (user, /etc, /var/root, others).
SUS_RC_RE='(curl|wget)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|/bin/)?sh|eval[[:space:]].*base64|base64[[:space:]]+(-d|-D|--decode)[^|]*\|[[:space:]]*(ba|z)?sh|DYLD_INSERT_LIBRARIES'
# Permission bits as octal digits; 0 if unreadable/garbled (keeps $((8#…)) safe).
perm_of() {
  local m
  m=$(stat -f "%Lp" "$1" 2>/dev/null)
  case "$m" in ''|*[!0-7]*) echo 0 ;; *) echo "$m" ;; esac
}
is_macho() { file -b "$1" 2>/dev/null | grep -q "Mach-O"; }
# Octal permission bits → true if writable by someone other than root.
# Owner not root, other-writable, or group-writable with a non-wheel group.
writable_by_nonroot() {
  local f="$1" owner group mode
  [ -e "$f" ] || return 1
  owner=$(stat -f "%Su" "$f" 2>/dev/null); group=$(stat -f "%Sg" "$f" 2>/dev/null)
  mode=$(perm_of "$f"); mode=${mode:-0}
  [ "$owner" != "root" ] && return 0
  [ $(( 8#$mode & 2 )) -ne 0 ] && return 0
  [ $(( 8#$mode & 16 )) -ne 0 ] && [ "$group" != "wheel" ] && return 0
  return 1
}
# Suspicious place for an executable that runs automatically.
suspicious_location() {
  case "$1" in
    # well-known dev toolchain dot-dirs are hidden but normal
    */.local/*|*/.cargo/*|*/.nvm/*|*/.pyenv/*|*/.volta/*|*/.bun/*|*/.deno/*|*/.rbenv/*|*/.asdf/*|*/.orbstack/*|*/.docker/*) return 1 ;;
    /tmp/*|/private/tmp/*|/private/var/tmp/*|/var/tmp/*|/Users/Shared/*) return 0 ;;
    */.[!.]*/*|*/.[!.]*) return 0 ;;   # any hidden path component
  esac
  return 1
}

# ---------- Full Disk Access probe ----------
# `[ -r TCC.db ]` only checks POSIX bits (always true); TCC blocks the actual
# open. Reading one byte is the real test.
USER_TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
SYS_TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
HAS_FDA=false
head -c1 "$USER_TCC_DB" >/dev/null 2>&1 && HAS_FDA=true

# ============================================================
# MODE: --purge-quarantine — the only path that actually deletes
# ============================================================
if [ "${1:-}" = "--purge-quarantine" ]; then
  echo -e "${BOLD}Quarantine contents:${RESET}"
  if [ -z "$(ls -A "$QUARANTINE_DIR" 2>/dev/null)" ]; then
    echo "Quarantine is empty. Nothing to purge."
    exit 0
  fi
  du -sh "$QUARANTINE_DIR"/*/* 2>/dev/null
  echo ""
  echo -e "${RED}${BOLD}This permanently deletes everything listed above. Cannot be undone.${RESET}"
  echo "Type PURGE to confirm, anything else to abort:"
  read -r CONFIRM
  if [ "$CONFIRM" = "PURGE" ]; then
    rm -rf "${QUARANTINE_DIR:?}"/*
    echo -e "${GREEN}Quarantine emptied.${RESET}"
  else
    echo -e "${YELLOW}Aborted. Quarantine untouched.${RESET}"
  fi
  exit 0
fi

QUARANTINE_MODE=false
[ "${1:-}" = "--quarantine" ] && QUARANTINE_MODE=true
if [ "$QUARANTINE_MODE" = true ] && [ "$IS_ROOT" = true ]; then
  echo -e "${RED}--quarantine refuses to run under sudo${RESET} (moving files as root can"
  echo "grab root-owned items and leaves root-owned files in your home)."
  echo "Run the sudo pass read-only, then run --quarantine as yourself."
  exit 1
fi

# Under sudo, hand every file this run creates back to the audited user,
# even if the run is interrupted.
if [ "$IS_ROOT" = true ] && [ "$TARGET_USER" != "root" ]; then
  trap 'chown -R "$TARGET_USER" "$AUDIT_DIR" 2>/dev/null; chown "$TARGET_USER" "$MD_REPORT" "$OUT_DIR/inventory.json" 2>/dev/null' EXIT
fi

PRIV_DESC="user ($TARGET_USER)"
[ "$IS_ROOT" = true ] && PRIV_DESC="root via sudo — auditing user $TARGET_USER + root-only checks"
FDA_DESC=$([ "$HAS_FDA" = true ] && echo "yes" || echo "no (TCC + Library sizes limited)")

echo "" > "$REPORT"
MACOS_VER="$(sw_vers -productVersion 2>/dev/null)"
MACOS_BUILD="$(sw_vers -buildVersion 2>/dev/null)"
HOSTNAME_HR="$(scutil --get ComputerName 2>/dev/null || hostname)"
{
  echo "# mac_audit report — $(date '+%Y-%m-%d %H:%M:%S')"
  echo ""
  echo "| | |"
  echo "|---|---|"
  echo "| Host | $HOSTNAME_HR |"
  echo "| macOS | ${MACOS_VER:-unknown} (${MACOS_BUILD:-?}) |"
  echo "| Mode | $([ "$QUARANTINE_MODE" = true ] && echo "QUARANTINE (moves junk after confirmation, never deletes)" || echo "READ-ONLY (nothing touched)") |"
  echo "| Privileges | $PRIV_DESC |"
  echo "| Full Disk Access | $FDA_DESC |"
  echo "| Text report | \`$REPORT\` |"
} > "$MD_REPORT"

clear
logt "${BOLD}mac_audit.sh — $(date)${RESET}"
logt "Host  : $HOSTNAME_HR — macOS ${MACOS_VER:-unknown} (${MACOS_BUILD:-?})"
logt "Report: $REPORT"
logt "MD    : $MD_REPORT"
logt "Mode  : $([ "$QUARANTINE_MODE" = true ] && echo "QUARANTINE (will offer to move junk, never deletes)" || echo "READ-ONLY (nothing will be touched)")"
logt "Privs : $PRIV_DESC"
logt "FDA   : $FDA_DESC"
[ "$IS_ROOT" = false ] && logt "        (tip: 'sudo bash $0' adds root-only checks: BTM, /var/root, all users, sudoers)"

# ============================================================
# [1] SYSTEM SECURITY POSTURE
# ============================================================
section "SYSTEM SECURITY POSTURE"

SIP=$(csrutil status 2>/dev/null | grep -o "enabled\|disabled")
log "  SIP (System Integrity Protection): $([ "$SIP" = "enabled" ] && echo "${GREEN}enabled${RESET}" || echo "${RED}${SIP:-unknown}${RESET}")"

GATEKEEPER=$(spctl --status 2>/dev/null)
log "  Gatekeeper: $(echo "$GATEKEEPER" | grep -q "assessments enabled" && echo "${GREEN}enabled${RESET}" || echo "${RED}$GATEKEEPER${RESET}")"

FV=$(fdesetup status 2>/dev/null)
log "  FileVault: $(echo "$FV" | grep -q "On" && echo "${GREEN}On${RESET}" || echo "${YELLOW}$FV${RESET}")"

FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
log "  Application Firewall: $(echo "$FW" | grep -qi "enabled" && echo "${GREEN}enabled${RESET}" || echo "${YELLOW}$FW${RESET}")"

STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
log "  Firewall stealth mode: $(echo "$STEALTH" | grep -qi "enabled" && echo "${GREEN}enabled${RESET}" || echo "${YELLOW}disabled${RESET}")"

ROOT_ENABLED=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null)
log "  Root account: $([ -n "$ROOT_ENABLED" ] && echo "${RED}ENABLED — disable unless you specifically need it${RESET}" || echo "${GREEN}disabled (default)${RESET}")"
[ -n "$ROOT_ENABLED" ] && REVIEW_ONLY+=("Root account is enabled (dsenableroot -d to disable)")

# Sealed System Volume: with authenticated-root disabled the system volume
# can be modified and booted unsealed — only ever done deliberately.
AUTHROOT=$(csrutil authenticated-root status 2>/dev/null | grep -o "enabled\|disabled")
if [ -n "$AUTHROOT" ]; then
  log "  Sealed system volume (authenticated root): $([ "$AUTHROOT" = "enabled" ] && echo "${GREEN}enabled${RESET}" || echo "${RED}disabled${RESET}")"
  [ "$AUTHROOT" = "disabled" ] && REVIEW_ONLY+=("Authenticated root (sealed system volume) is DISABLED")
fi
[ "$SIP" = "disabled" ] && REVIEW_ONLY+=("SIP is disabled")
echo "$GATEKEEPER" | grep -q "assessments enabled" || REVIEW_ONLY+=("Gatekeeper is not enabled")

# XProtect: Apple's built-in signature AV. Updates arrive silently via
# "Install Security Responses and system files" (ConfigDataInstall).
XP_PLIST="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
XP_VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$XP_PLIST" 2>/dev/null)
XP_DATE=$(stat -f "%Sm" -t "%Y-%m-%d" "$XP_PLIST" 2>/dev/null)
log "  XProtect definitions: ${XP_VER:-unknown}${XP_DATE:+ (updated $XP_DATE)}"
if [ -n "$XP_DATE" ]; then
  XP_AGE=$(( ( $(date +%s) - $(date -j -f "%Y-%m-%d" "$XP_DATE" +%s 2>/dev/null || date +%s) ) / 86400 ))
  if [ "$XP_AGE" -gt 60 ]; then
    log "    ${YELLOW}XProtect not updated in ${XP_AGE} days — check automatic security updates below.${RESET}"
    REVIEW_ONLY+=("XProtect definitions ${XP_AGE} days old")
  fi
fi

log "  Automatic update settings (unset = Apple default, on):"
SU_PREFS="/Library/Preferences/com.apple.SoftwareUpdate"
for KEY in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall ConfigDataInstall AutomaticallyInstallMacOSUpdates; do
  VAL=$(defaults read "$SU_PREFS" "$KEY" 2>/dev/null)
  case "$VAL" in
    1) log "    $KEY: ${GREEN}on${RESET}" ;;
    0) if [ "$KEY" = "CriticalUpdateInstall" ] || [ "$KEY" = "ConfigDataInstall" ]; then
         log "    $KEY: ${RED}OFF — security responses / XProtect updates will not install automatically${RESET}"
         REVIEW_ONLY+=("Software Update $KEY is off (security data not auto-installed)")
       else
         log "    $KEY: ${YELLOW}off${RESET}"
       fi ;;
    *) log "    $KEY: default" ;;
  esac
done

# Auto-login defeats FileVault's pre-boot auth on the login window and
# stores the password XOR-obfuscated (trivially reversible) in /etc/kcpassword.
AUTOLOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -n "$AUTOLOGIN" ] || [ -e /etc/kcpassword ]; then
  log "  Automatic login: ${RED}ENABLED${AUTOLOGIN:+ for $AUTOLOGIN}${RESET}$([ -e /etc/kcpassword ] && echo " — /etc/kcpassword present (reversibly obfuscated password)")"
  REVIEW_ONLY+=("Automatic login enabled${AUTOLOGIN:+ ($AUTOLOGIN)}; /etc/kcpassword $([ -e /etc/kcpassword ] && echo present || echo absent)")
else
  log "  Automatic login: ${GREEN}disabled${RESET}"
fi
GUEST=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
log "  Guest account: $([ "$GUEST" = "1" ] && echo "${YELLOW}enabled${RESET}" || echo "${GREEN}disabled${RESET}")"
[ "$GUEST" = "1" ] && note_mod "Guest account enabled"

SCREENLOCK=$(as_user sysadminctl -screenLock status 2>&1 | sed -n 's/.*\(screenLock.*\)/\1/p' | head -1)
[ -n "$SCREENLOCK" ] && log "  Screen lock: $SCREENLOCK"
LDM=$(as_user defaults read .GlobalPreferences LDMGlobalEnabled 2>/dev/null)
log "  Lockdown Mode: $([ "$LDM" = "1" ] && echo "on" || echo "off (default)")"

# DYLD_INSERT_LIBRARIES in launchd's environment injects a dylib into every
# process launched afterwards in that domain — pure red flag.
LD_DYLD=$(as_user launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null)
if [ -n "$LD_DYLD" ]; then
  log "  ${RED}[INJECTION]${RESET} launchd environment has DYLD_INSERT_LIBRARIES=$LD_DYLD"
  REVIEW_ONLY+=("launchd DYLD_INSERT_LIBRARIES set: $LD_DYLD")
fi

SOFTWARE_UPDATE_AGE=$(softwareupdate --history 2>/dev/null | tail -2 | head -1)
log "  Last installed system update: ${SOFTWARE_UPDATE_AGE:-unknown}"

# ============================================================
# [2] INSTALLED SOFTWARE INVENTORY (auto-discovery)
# ============================================================
section "INSTALLED SOFTWARE INVENTORY"

echo "{" > "$INVENTORY"
echo "  \"generated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$INVENTORY"

log "\n  ${BOLD}Applications (/Applications, ~/Applications):${RESET}"
echo "  \"applications\": [" >> "$INVENTORY"
FIRST=true
while IFS= read -r APP; do
  NAME=$(basename "$APP" .app)
  VERSION=$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  LAST_USED=$(mdls -name kMDItemLastUsedDate -raw "$APP" 2>/dev/null | cut -d' ' -f1)
  [ "$LAST_USED" = "(null)" ] && LAST_USED=""  # mdls prints literal "(null)" when unset
  SIGNED="unsigned"
  codesign --verify --deep --strict "$APP" >/dev/null 2>&1 && SIGNED="signed"
  # codesign --deep --strict routinely fails on legitimately signed apps whose
  # updaters modified nested helpers in place (Chrome, Firefox, GIMP were all
  # false-flagged on the 2026-07-03 run). Gatekeeper's own assessment is the
  # authoritative check; only apps failing BOTH are worth review.
  if [ "$SIGNED" = "unsigned" ] && spctl --assess --type execute "$APP" >/dev/null 2>&1; then
    SIGNED="gatekeeper-ok"
  fi
  log "    $NAME ($VERSION) — last used: ${LAST_USED:-never recorded} — $SIGNED"
  [ "$SIGNED" = "unsigned" ] && REVIEW_ONLY+=("UNSIGNED APP (fails codesign AND Gatekeeper): $APP")
  $FIRST || echo "," >> "$INVENTORY"; FIRST=false
  printf '    {"name": "%s", "version": "%s", "last_used": "%s", "signed": "%s"}' \
    "$(json_escape "$NAME")" "$(json_escape "${VERSION:-unknown}")" "${LAST_USED:-unknown}" "$SIGNED" >> "$INVENTORY"
done < <(find /Applications "$HOME/Applications" -maxdepth 1 -name "*.app" 2>/dev/null)
echo "" >> "$INVENTORY"; echo "  ]," >> "$INVENTORY"

log "\n  ${BOLD}Homebrew:${RESET}"
echo "  \"homebrew_outdated\": [" >> "$INVENTORY"
if command -v brew >/dev/null 2>&1; then
  OUTDATED=$(as_user "$(command -v brew)" outdated 2>/dev/null)
  if [ -n "$OUTDATED" ]; then
    log "    ${YELLOW}Outdated formulae/casks:${RESET}"
    echo "$OUTDATED" | while read -r LINE; do log "      $LINE"; done
    echo "$OUTDATED" | awk '{printf "\"%s\",", $1}' | sed 's/,$//' >> "$INVENTORY"
  else
    log "    All formulae/casks up to date."
  fi
else
  log "    Homebrew not installed."
fi
echo "" >> "$INVENTORY"; echo "  ]," >> "$INVENTORY"

log "\n  ${BOLD}Mac App Store (via 'mas', if installed):${RESET}"
if command -v mas >/dev/null 2>&1; then
  as_user "$(command -v mas)" outdated 2>/dev/null | while read -r LINE; do log "    ${YELLOW}[OUTDATED]${RESET} $LINE"; done
else
  log "    'mas' CLI not installed — skip (install with: brew install mas)"
fi

log "\n  ${BOLD}Global pip / npm packages (extra attack surface):${RESET}"
command -v pip3 >/dev/null 2>&1 && as_user "$(command -v pip3)" list --user 2>/dev/null | tail -n +3 | while read -r LINE; do log "    [pip --user] $LINE"; done
command -v npm  >/dev/null 2>&1 && as_user "$(command -v npm)" list -g --depth=0 2>/dev/null | tail -n +2 | \
  sed 's/^[^A-Za-z0-9@]*//' | grep -v '^ *$' | while read -r LINE; do log "    [npm -g] $LINE"; done

# Installer receipts: everything ever installed via .pkg that isn't Apple's.
# Receipts survive even when the app was dragged to the Trash — good memory
# of past non-factory installs (drivers, audio tools, corporate agents).
log "\n  ${BOLD}Non-Apple installer receipts (pkgutil):${RESET}"
PKG_RECEIPTS=$(pkgutil --pkgs 2>/dev/null | grep -vE '^com\.apple\.' | sort)
if [ -n "$PKG_RECEIPTS" ]; then
  echo "$PKG_RECEIPTS" | while read -r LINE; do log "    $LINE"; done
  note_mod "$(echo "$PKG_RECEIPTS" | wc -l | tr -d ' ') non-Apple installer receipts (see section 2)"
else
  log "    None found."
fi

echo "  \"note\": \"machine-readable inventory for the weekly research task\"" >> "$INVENTORY"
echo "}" >> "$INVENTORY"

# ============================================================
# [3] UNUSED THIRD-PARTY SOFTWARE (review, never auto-delete)
# ============================================================
section "UNUSED THIRD-PARTY SOFTWARE (>90 days untouched)"
log "  These are candidates to uninstall or update — review only, not auto-flagged.\n"

NOW_EPOCH=$(date +%s)
# NOTE: process substitution (not a pipe) — a piped `while` runs in a subshell,
# so REVIEW_ONLY+=() inside it silently updated a throwaway copy of the array
# and unused apps never reached the summary. Long-standing bug, fixed 2026-07.
while IFS= read -r APP; do
  LAST_USED=$(mdls -name kMDItemLastUsedDate -raw "$APP" 2>/dev/null | cut -d' ' -f1)
  if [ -n "$LAST_USED" ] && [ "$LAST_USED" != "(null)" ]; then
    LAST_EPOCH=$(date -j -f "%Y-%m-%d" "$LAST_USED" +%s 2>/dev/null)
    if [ -n "$LAST_EPOCH" ]; then
      DAYS=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))
      if [ "$DAYS" -gt 90 ]; then
        log "  ${YELLOW}[UNUSED ${DAYS}d]${RESET} $(basename "$APP") — last opened $LAST_USED"
        REVIEW_ONLY+=("UNUSED APP ($DAYS days): $APP")
      fi
    fi
  fi
done < <(find /Applications -maxdepth 1 -name "*.app" 2>/dev/null)

# ============================================================
# [4] LOCAL AI TOOLS (incl. Odysseus) — extra scrutiny
# ============================================================
section "LOCAL AI TOOLS"
log "  Local AI runners have an unusually large attack surface: they often\n  bind a local HTTP server, run shell/MCP tools, and read your files.\n"

# NOTE: macOS ships bash 3.2 as /bin/bash (no `declare -A` / associative array
# support, added in bash 4.0). These are written as parallel indexed arrays
# (same index = matching pair) so the script runs unmodified on stock macOS bash.
AI_TOOL_NAMES=(
  "Ollama.app"
  "LM Studio.app"
  "Odysseus.app"
  "GPT4All.app"
  "Jan.app"
)
AI_TOOL_NOTES=(
  "Ollama — check it's bound to 127.0.0.1, not 0.0.0.0"
  "LM Studio — check server tab for exposed network binding"
  "Odysseus AI — self-hosted workspace with shell/MCP/web access. High-value target: audit its bound port, installed MCP tools, and email/calendar integrations."
  "GPT4All"
  "Jan"
)

for IDX in "${!AI_TOOL_NAMES[@]}"; do
  APP_NAME="${AI_TOOL_NAMES[$IDX]}"
  FOUND=""
  [ -d "/Applications/$APP_NAME" ] && FOUND="/Applications/$APP_NAME"
  [ -d "$HOME/Applications/$APP_NAME" ] && FOUND="$HOME/Applications/$APP_NAME"
  if [ -n "$FOUND" ]; then
    log "  ${YELLOW}[FOUND]${RESET} $APP_NAME"
    log "    Note: ${AI_TOOL_NOTES[$IDX]}"
    log "    Path: $FOUND"
  fi
done

# --- CLI/daemon AI runners (added 2026-07-03) ---
# The 2026-07-03 audit run had llama-server listening on *:8000 via a
# LaunchAgent while this section reported nothing — it only looked for .app
# bundles. Homebrew-installed runners and login-item daemons are the more
# dangerous case (headless, always-on, no menu bar icon reminding you).
log "\n  ${BOLD}CLI/daemon AI runners:${RESET}"
for BIN in ollama llama-server lms mlx_lm.server; do
  BINPATH=$(command -v "$BIN" 2>/dev/null)
  [ -n "$BINPATH" ] && log "  ${YELLOW}[INSTALLED]${RESET} $BIN → $BINPATH"
done
ps axo comm= 2>/dev/null | grep -E '(^|/)(ollama|llama-server|lms|mlx_lm\.server)$' | sort -u | while read -r P; do
  log "  ${YELLOW}[RUNNING]${RESET} $P — check the port list below for its binding"
done

# LaunchAgents that auto-start an AI server at login: flag explicit 0.0.0.0
# binds. (llama-server defaults to 127.0.0.1 — an exposed bind means someone
# passed --host 0.0.0.0, deliberately or by copy-paste.)
while IFS= read -r PL; do
  PLARGS=$(plutil -p "$PL" 2>/dev/null)
  if echo "$PLARGS" | grep -qE 'llama-server|ollama|mlx_lm'; then
    log "  ${YELLOW}[AUTOSTART]${RESET} $(basename "$PL") launches an AI server at login."
    if echo "$PLARGS" | grep -q '0\.0\.0\.0'; then
      log "    ${RED}Binds 0.0.0.0 — reachable from the whole network. Change to --host 127.0.0.1 and reload the agent.${RESET}"
      REVIEW_ONLY+=("AI server LaunchAgent bound to 0.0.0.0: $PL")
    fi
  fi
done < <(find "$HOME/Library/LaunchAgents" -maxdepth 1 -name "*.plist" 2>/dev/null)

# --- version_lt: portable dotted-version comparison (no GNU sort -V, which ---
# macOS's BSD `sort` doesn't have). Returns 0 (true) if $1 < $2, else 1.
version_lt() {
  local a="$1" b="$2"
  local IFS=.
  local -a A=($a) B=($b)
  local i n=${#A[@]}
  [ ${#B[@]} -gt "$n" ] && n=${#B[@]}
  for ((i=0; i<n; i++)); do
    local av=${A[i]:-0} bv=${B[i]:-0}
    # Strip any non-digit suffix (e.g. "1-rc2") — 10#$av crashes on non-numerics.
    av=${av%%[!0-9]*}; bv=${bv%%[!0-9]*}
    av=$((10#${av:-0})); bv=$((10#${bv:-0}))
    if [ "$av" -lt "$bv" ]; then return 0; fi
    if [ "$av" -gt "$bv" ]; then return 1; fi
  done
  return 1
}

# --- Ollama version check: CVE-2026-7482 "Bleeding Llama" (CVSS 9.1) ---
# Unauthenticated heap out-of-bounds read in the GGUF model loader (fs/ggml/gguf.go,
# server/quantization.go) reachable via the /api/create endpoint. Leaks process memory
# (env vars, API keys, system prompts, other users' conversations). Fixed in 0.17.1.
# Source: runZero / Cyera "Bleeding Llama" / SentinelOne / TheHackerNews, May 2026.
if command -v ollama >/dev/null 2>&1; then
  OLLAMA_VER=$(ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -n "$OLLAMA_VER" ]; then
    OLLAMA_MIN_SAFE="0.17.1"
    if version_lt "$OLLAMA_VER" "$OLLAMA_MIN_SAFE"; then
      log "  ${RED}[VULNERABLE]${RESET} Ollama $OLLAMA_VER — below 0.17.1, exposed to CVE-2026-7482 (Bleeding Llama, CVSS 9.1)."
      log "    Unauthenticated memory leak via /api/create. Update Ollama to >= 0.17.1."
      REVIEW_ONLY+=("Ollama $OLLAMA_VER — CVE-2026-7482, update to >= 0.17.1")
    else
      log "  Ollama $OLLAMA_VER — at or above 0.17.1, not exposed to CVE-2026-7482."
    fi
  fi
fi

log "\n  Listening ports bound to non-localhost (potential remote exposure of local AI servers):"
# FIX 2026-07: the old filter excluded "*:" — but "*:port" is lsof's notation for
# a wildcard bind (0.0.0.0/all interfaces), i.e. exactly the exposed case this
# check exists to catch. The filter was inverted: it hid real exposures and the
# check could never fire for the most common misconfiguration. Now only loopback
# binds (127.0.0.1, ::1, localhost) are excluded.
# Process substitution (not a pipe) so exposures reach the summary.
EXPOSED_N=0
while IFS= read -r LINE; do
  [ -z "$LINE" ] && continue
  EXPOSED_N=$((EXPOSED_N + 1))
  log "    ${RED}[EXPOSED?]${RESET} $LINE"
done < <(lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{print $1, $9}' | sort -u | grep -v "127\.0\.0\.1\|\[::1\]\|localhost")
[ "$EXPOSED_N" -gt 0 ] && REVIEW_ONLY+=("$EXPOSED_N listening socket(s) bound beyond localhost (section 4) — confirm each is meant to be reachable")
[ "$IS_ROOT" = false ] && log "  (Only your own processes are visible; the sudo run lists every listener.)"
log "  (If this list is non-empty, confirm each one is meant to be reachable from outside this Mac.)"

# ============================================================
# [5] LEGACY / SUSPICIOUS ARTIFACTS
# ============================================================
section "LEGACY & SUSPICIOUS HOME ARTIFACTS"

SUSPICIOUS_HOME_PATHS=(
  ".matplotlib"
  ".Trash-1000"
  ".start_app_logs"
  ".oracle_jre_usage"
  ".tracker.prefs"
  ".DDLocalBackups"
  ".DDPreview"
  ".adobe"
  ".mono"
  ".mplayer"
  ".Wurst encryption"
  ".zprofile.pysave"
  "package-lock.json"
  ".chatgpt_history"
)
SUSPICIOUS_HOME_REASONS=(
  "Should be user-owned. Root ownership is abnormal."
  "Linux trash artifact. Not native to macOS."
  "Unknown logger. Non-standard."
  "Oracle JRE telemetry."
  "Linux GNOME tracker. Not native to macOS."
  "Disk Drill backup data."
  "Disk Drill preview data."
  "Adobe telemetry."
  "Old .NET runtime."
  "Dead media player config."
  "Minecraft hacking client artifact."
  "Stale shell backup."
  "Node artifact in wrong location (home dir)."
  "Often an empty stray file."
)

for IDX in "${!SUSPICIOUS_HOME_PATHS[@]}"; do
  DIR="${SUSPICIOUS_HOME_PATHS[$IDX]}"
  FULL="$HOME/$DIR"
  if [ -e "$FULL" ]; then
    OWNER=$(stat -f "%Su" "$FULL" 2>/dev/null)
    SIZE=$(du -sh "$FULL" 2>/dev/null | cut -f1)
    MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d" "$FULL" 2>/dev/null)
    log "\n  ${RED}[FOUND]${RESET} ~/$DIR"
    log "    Reason   : ${SUSPICIOUS_HOME_REASONS[$IDX]}"
    log "    Owner    : $OWNER   Size: $SIZE   Modified: $MODIFIED"
    if [ "$OWNER" = "root" ]; then
      log "    ${RED}Owned by root — manual review only, will not be quarantined.${RESET}"
      REVIEW_ONLY+=("$FULL (root-owned)")
    else
      SAFE_CANDIDATES+=("$FULL")
    fi
  fi
done

SUSPICIOUS_LIB_PATHS=(
  "NGL"
  "DES"
  "FinanceBackup"
  "Staging"
  "Trial"
  "PhotoshopCrashes"
  "Application Support/Google/GoogleUpdate.app"
)
SUSPICIOUS_LIB_REASONS=(
  "Anonymous messaging app. Known data harvester."
  "Unknown origin. Not a standard macOS directory."
  "Non-standard. Unclear what is backing up finance data."
  "Non-standard macOS Library folder."
  "Non-standard macOS Library folder."
  "Adobe crash telemetry."
  "SHub 'Reaper' infostealer IOC (disclosed May 2026): fake Google Update LaunchAgent payload location. The real Google Keystone updater lives at ~/Library/Google/GoogleSoftwareUpdate, NOT here. Treat as suspected active malware, not routine telemetry. Source: SentinelOne, Help Net Security."
)
for IDX in "${!SUSPICIOUS_LIB_PATHS[@]}"; do
  DIR="${SUSPICIOUS_LIB_PATHS[$IDX]}"
  FULL="$HOME/Library/$DIR"
  if [ -e "$FULL" ]; then
    SIZE=$(du -sh "$FULL" 2>/dev/null | cut -f1)
    log "\n  ${YELLOW}[FOUND]${RESET} ~/Library/$DIR — ${SUSPICIOUS_LIB_REASONS[$IDX]} (${SIZE:-size unreadable})"
    REVIEW_ONLY+=("$FULL")
  fi
done

# Hidden (dot-prefixed) entries in Library dirs: legitimate software almost
# never hides there; AdLoad/Atomic/Poseidon-style stealers routinely do
# (e.g. ~/Library/Application Support/.<random>/).
log "\n  ${BOLD}Hidden entries in Library folders (should be none besides .DS_Store/.localized):${RESET}"
HIDDEN_LIB_FOUND=false
for LBASE in "$HOME/Library" "$HOME/Library/Application Support" "$HOME/Library/LaunchAgents" \
             "/Library" "/Library/Application Support" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  [ -d "$LBASE" ] || continue
  while IFS= read -r HE; do
    [ -z "$HE" ] && continue
    HIDDEN_LIB_FOUND=true
    HP="$LBASE/$HE"
    log "    ${YELLOW}[HIDDEN]${RESET} $HP ($(stat -f "%Su, modified %Sm" -t "%Y-%m-%d" "$HP" 2>/dev/null))"
    REVIEW_ONLY+=("Hidden entry in Library: $HP")
  done < <(ls -A "$LBASE" 2>/dev/null | grep '^\.' | grep -vE '^\.(DS_Store|localized|com\.apple\.timemachine\.supported)$')
done
[ "$HIDDEN_LIB_FOUND" = false ] && log "    None."

# /Users/Shared is world-writable and survives across accounts — a classic
# drop zone for payloads and cross-user persistence.
log "\n  ${BOLD}/Users/Shared (world-writable drop zone):${RESET}"
SHARED_LIST=$(ls -A /Users/Shared 2>/dev/null | grep -vE '^\.(localized|DS_Store)$')
if [ -n "$SHARED_LIST" ]; then
  echo "$SHARED_LIST" | while IFS= read -r I; do log "    $I"; done
  note_mod "/Users/Shared contains $(echo "$SHARED_LIST" | wc -l | tr -d ' ') item(s)"
else
  log "    Empty (factory)."
fi

# Executables in shared/temp locations: droppers stage here before
# installing persistence. Scripts and Mach-O only; installer debris is noise.
log "\n  ${BOLD}Executables staged in shared / temp locations:${RESET}"
TMPEXEC_FOUND=false
while IFS= read -r TX; do
  [ -z "$TX" ] && continue
  KIND=$(file -b "$TX" 2>/dev/null | cut -c1-60)
  case "$KIND" in *Mach-O*|*script*|*executable*) ;; *) continue ;; esac
  TMPEXEC_FOUND=true
  log "    ${RED}[EXEC]${RESET} $TX — $KIND — owner $(stat -f "%Su" "$TX" 2>/dev/null), $(sig_status "$TX")"
  REVIEW_ONLY+=("Executable in shared/temp location: $TX ($KIND)")
done < <(find /Users/Shared /private/tmp /private/var/tmp "${TMPDIR:-/nonexistent}" -maxdepth 3 -type f -perm -100 2>/dev/null | head -50)
[ "$TMPEXEC_FOUND" = false ] && log "    None."

# ============================================================
# [6] ACTIVE DATA COLLECTORS
# ============================================================
section "ACTIVE DATA COLLECTORS (phone-home logs, informational only)"

COLLECTOR_PATHS=(
  ".copilot"
  ".codex"
  ".claude"
  "Library/Google"
)
COLLECTOR_NOTES=(
  "GitHub Copilot — Microsoft telemetry"
  "OpenAI Codex CLI — local logs"
  "Anthropic Claude CLI — local logs"
  "Google telemetry"
)
for IDX in "${!COLLECTOR_PATHS[@]}"; do
  DIR="${COLLECTOR_PATHS[$IDX]}"
  FULL="$HOME/$DIR"
  if [ -e "$FULL" ]; then
    SIZE=$(du -sh "$FULL" 2>/dev/null | cut -f1)
    log "  ${YELLOW}[ACTIVE]${RESET} ~/$DIR — ${COLLECTOR_NOTES[$IDX]} ($SIZE)"
  fi
done

# ============================================================
# [7] TCC PRIVACY PERMISSIONS
# ============================================================
section "TCC PRIVACY PERMISSIONS (what can access your data)"

# FIX: the old check only read the USER TCC.db, but Full Disk Access,
# Accessibility, Screen Recording and Input Monitoring grants are stored in
# the SYSTEM TCC.db — so the most dangerous grants were never shown. Both
# are read now, and the readability test is a real read (see HAS_FDA).
# auth_value: 0 denied, 2 allowed, 3 limited.
TCC_SERVICES="kTCCServiceSystemPolicyAllFiles kTCCServiceAccessibility kTCCServiceScreenCapture kTCCServiceListenEvent kTCCServicePostEvent kTCCServiceMicrophone kTCCServiceCamera kTCCServiceAppleEvents kTCCServiceSystemPolicyDesktopFolder kTCCServiceSystemPolicyDocumentsFolder kTCCServiceSystemPolicyDownloadsFolder kTCCServiceSystemPolicyRemovableVolumes kTCCServiceSystemPolicyNetworkVolumes kTCCServiceEndpointSecurityClient kTCCServiceDeveloperTool"
TCC_ANY=false
for DBINFO in "user|$USER_TCC_DB" "system|$SYS_TCC_DB"; do
  DBLABEL="${DBINFO%%|*}"; DB="${DBINFO#*|}"
  if ! head -c1 "$DB" >/dev/null 2>&1; then
    log "  ${YELLOW}$DBLABEL TCC.db not readable${RESET} — grant Terminal Full Disk Access (System Settings → Privacy & Security → Full Disk Access)."
    continue
  fi
  TCC_ANY=true
  log "\n  ${BOLD}[$DBLABEL TCC.db]${RESET}"
  for SERVICE in $TCC_SERVICES; do
    ROWS=$(sqlite3 "$DB" "SELECT client, client_type, auth_value FROM access WHERE service='$SERVICE' ORDER BY auth_value DESC, client;" 2>/dev/null)
    [ -z "$ROWS" ] && continue
    log "    ${SERVICE#kTCCService}:"
    while IFS='|' read -r CLIENT CTYPE AUTH; do
      case "$AUTH" in
        2) STATUS="${RED}ALLOWED${RESET}" ;;
        3) STATUS="${YELLOW}LIMITED${RESET}" ;;
        *) STATUS="${GREEN}denied${RESET}" ;;
      esac
      EXTRA=""
      # client_type 1 = absolute path. A grant to a path that no longer
      # exists can be re-used by anything dropped at that path.
      if [ "$CTYPE" = "1" ] && [ ! -e "$CLIENT" ]; then
        EXTRA=" ${YELLOW}(stale — path no longer exists)${RESET}"
        [ "$AUTH" = "2" ] && REVIEW_ONLY+=("Stale TCC grant ${SERVICE#kTCCService} → missing path $CLIENT (remove in Privacy & Security)")
      fi
      log "      $STATUS — $CLIENT$EXTRA"
      if [ "$AUTH" = "2" ]; then
        case "$SERVICE" in
          kTCCServiceSystemPolicyAllFiles|kTCCServiceAccessibility|kTCCServiceScreenCapture|kTCCServiceListenEvent|kTCCServicePostEvent)
            case "$CLIENT" in com.apple.*|/System/*|/usr/libexec/*) ;; *) note_mod "TCC ${SERVICE#kTCCService} granted to $CLIENT" ;; esac ;;
        esac
      fi
    done <<< "$ROWS"
  done
done
[ "$TCC_ANY" = false ] && log "  (Nothing readable — both databases need Full Disk Access.)"

# ============================================================
# [8] LAUNCH AGENTS & DAEMONS
# ============================================================
section "LAUNCH AGENTS & DAEMONS (auto-start persistence)"

# Under sudo, every other account's LaunchAgents (and root's) are audited too.
LAUNCH_DIRS=("$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons")
if [ "$IS_ROOT" = true ]; then
  for UH in /Users/* /var/root; do
    [ "$UH" = "$HOME" ] && continue
    [ -d "$UH/Library/LaunchAgents" ] && LAUNCH_DIRS+=("$UH/Library/LaunchAgents")
  done
fi
INTERPRETERS='^(/bin/(ba|z|da|k|c|tc)?sh|/usr/bin/(env|python3?|perl|ruby|osascript|node)|/usr/local/bin/(python3?|node)|/opt/homebrew/bin/(python3?|node))$'

# FIX: this loop used to be `find | grep | while` — a subshell — so the
# SHub/AdLoad IOC hits below were appended to a throwaway copy of REVIEW_ONLY
# and NEVER reached the summary (same bug fixed in section 3 in 2026-07).
for LAUNCH_DIR in "${LAUNCH_DIRS[@]}"; do
  if [ -d "$LAUNCH_DIR" ]; then
    log "\n  ${BOLD}$LAUNCH_DIR:${RESET}"
    RUNS_AS_ROOT=false
    [ "$LAUNCH_DIR" = "/Library/LaunchDaemons" ] && RUNS_AS_ROOT=true
    while IFS= read -r PLIST; do
      [ -z "$PLIST" ] && continue
      PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$PLIST" 2>/dev/null)
      [ -z "$PROGRAM" ] && PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :Program" "$PLIST" 2>/dev/null)
      # Fallback (added 2026-07-03): both keystone plists showed "unknown
      # binary" — PlistBuddy can fail on some plist layouts. plutil -p prints
      # any plist (binary or XML); grab the first ProgramArguments entry.
      [ -z "$PROGRAM" ] && PROGRAM=$(plutil -p "$PLIST" 2>/dev/null | \
        awk -F'"' '/"ProgramArguments"/{f=1; next} f && NF >= 2 {print $2; exit}')
      # com.apple.* labels used to be skipped outright — but Apple's own
      # plists live in /System/Library (SIP-protected); a com.apple.* name in
      # these third-party dirs is either an Apple-signed add-on (Xcode, etc.)
      # or malware masquerading as Apple. Signature decides.
      case "$(basename "$PLIST")" in
        com.apple.*)
          case "$(sig_status "$PROGRAM")" in
            *"Software Signing"*|*"Apple Mac OS Application Signing"*) continue ;;
          esac
          log "    ${RED}[MASQUERADE?]${RESET} $(basename "$PLIST") uses an Apple label but its program is not Apple-signed: ${PROGRAM:-unknown} ($(sig_status "$PROGRAM"))"
          REVIEW_ONLY+=("Apple-named launchd item with non-Apple program: $PLIST -> ${PROGRAM:-unknown}")
          continue ;;
      esac
      log "    ${YELLOW}[NON-APPLE]${RESET} $(basename "$PLIST") → ${PROGRAM:-unknown binary}"

      # --- SHub "Reaper" infostealer IOC (disclosed May 2026) ---
      # Drops a fake Google Software Update LaunchAgent named com.google.keystone.agent.plist
      # whose Program/ProgramArguments points at ~/Library/Application Support/Google/GoogleUpdate.app/...
      # (a base64-decoded bash script named GoogleUpdate), beaconing every 60s to a C2
      # /api/bot/heartbeat endpoint and executing whatever code it returns.
      # The LEGITIMATE Google Keystone updater uses the same plist name but its Program path
      # lives under ~/Library/Google/GoogleSoftwareUpdate/ — NOT under "Application Support/Google".
      # Path mismatch is the tell. Source: SentinelOne "SHub Reaper", Help Net Security, May 2026.
      PLIST_NAME=$(basename "$PLIST")
      if [ "$PLIST_NAME" = "com.google.keystone.agent.plist" ]; then
        # Check the parsed program path AND the raw plist dump — if program
        # extraction failed, the IOC check must not silently pass.
        if echo "$PROGRAM" | grep -qi "Application Support/Google" || \
           plutil -p "$PLIST" 2>/dev/null | grep -qi "Application Support/Google/GoogleUpdate"; then
          log "    ${RED}[SUSPECTED MALWARE]${RESET} $PLIST_NAME points at '$PROGRAM' — this matches the SHub \"Reaper\" infostealer's fake Google Update IOC (May 2026), NOT the legitimate Keystone path (~/Library/Google/GoogleSoftwareUpdate/). Manual review urgent — do not assume this is real Google software."
          REVIEW_ONLY+=("SUSPECTED MALWARE (SHub Reaper IOC): $PLIST -> $PROGRAM")
        fi
      fi

      # --- Adload / UpdateAgent random-name LaunchAgent pattern ---
      # AdLoad and UpdateAgent variants register LaunchAgents with long randomly-generated
      # label strings (e.g. com.shenbfgbvgsfssfmrynamdzyetzfnd.plist, org.<20+ random chars>.plist)
      # pointing at a similarly randomly-named folder under ~/Library/Application Support/.
      # Source: Microsoft WDSI, LevelBlue, eSentire, MITRE ATT&CK T1543.001.
      LABEL_BODY=$(echo "$PLIST_NAME" | sed -E 's/\.plist$//; s/^(com|org|net|io)\.//')
      if echo "$LABEL_BODY" | grep -Eq '^[a-z0-9]{20,}$' && ! echo "$LABEL_BODY" | grep -qiE 'google|apple|microsoft|adobe|docker|homebrew|jetbrains|spotify'; then
        log "    ${RED}[SUSPICIOUS NAME]${RESET} $PLIST_NAME — long randomly-generated label, matches AdLoad/UpdateAgent adware persistence pattern. Review Program path: ${PROGRAM:-unknown}"
        REVIEW_ONLY+=("SUSPICIOUS LaunchAgent (random-name pattern): $PLIST")
      fi

      # --- Program integrity (added 2026-09) ---
      # Interpreter launchers (sh/python/osascript …) hide the real payload
      # in the next argument — inspect that instead of /bin/sh.
      TARGET="$PROGRAM"
      if echo "$PROGRAM" | grep -Eq "$INTERPRETERS"; then
        ARG1=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:1" "$PLIST" 2>/dev/null)
        [ "$ARG1" = "-c" ] || [ "$ARG1" = "-e" ] && ARG1=""
        [ -n "$ARG1" ] && [ "${ARG1#/}" != "$ARG1" ] && TARGET="$ARG1"
        log "      via interpreter $PROGRAM${ARG1:+ → $ARG1}"
      fi
      PL_DUMP=$(plutil -p "$PLIST" 2>/dev/null)
      if echo "$PL_DUMP" | grep -Eq 'curl |wget |base64 (-d|-D|--decode)|/dev/tcp/|osascript -e|python3? -c|eval '; then
        log "      ${RED}[INLINE CODE]${RESET} arguments contain download/decode/eval — typical dropper persistence"
        REVIEW_ONLY+=("launchd item runs inline download/decode/eval code: $PLIST")
      fi
      if echo "$PL_DUMP" | grep -q 'DYLD_INSERT_LIBRARIES'; then
        log "      ${RED}[INJECTION]${RESET} sets DYLD_INSERT_LIBRARIES"
        REVIEW_ONLY+=("launchd item injects a dylib (DYLD_INSERT_LIBRARIES): $PLIST")
      fi
      if [ -n "$TARGET" ] && [ "${TARGET#/}" != "$TARGET" ]; then
        SIG=$(sig_status "$TARGET")
        log "      program: $TARGET — $SIG"
        if [ "$SIG" = "MISSING" ]; then
          note_mod "Stale launchd item (program missing): $PLIST"
        elif [ "$SIG" = "UNSIGNED" ] && is_macho "$TARGET"; then
          REVIEW_ONLY+=("Unsigned Mach-O launched at startup: $TARGET ($PLIST)")
        fi
        if suspicious_location "$TARGET"; then
          log "      ${RED}[LOCATION]${RESET} runs from a hidden/temp/shared path"
          REVIEW_ONLY+=("launchd program in hidden/temp/shared location: $TARGET ($PLIST)")
        fi
      fi
      # Privilege escalation: root runs whatever a non-root user can rewrite.
      if [ "$RUNS_AS_ROOT" = true ]; then
        DAEMON_USER=$(/usr/libexec/PlistBuddy -c "Print :UserName" "$PLIST" 2>/dev/null)
        if [ -z "$DAEMON_USER" ] || [ "$DAEMON_USER" = "root" ]; then
          if writable_by_nonroot "$PLIST"; then
            log "      ${RED}[PRIVESC]${RESET} plist is writable by non-root ($(stat -f '%Su:%Sg %Sp' "$PLIST" 2>/dev/null))"
            REVIEW_ONLY+=("PRIVESC: LaunchDaemon plist writable by non-root: $PLIST")
          fi
          if [ -n "$TARGET" ] && [ -e "$TARGET" ]; then
            if writable_by_nonroot "$TARGET" || writable_by_nonroot "$(dirname "$TARGET")"; then
              log "      ${RED}[PRIVESC]${RESET} root runs a program (or its folder) writable by non-root: $TARGET ($(stat -f '%Su:%Sg %Sp' "$TARGET" 2>/dev/null))"
              REVIEW_ONLY+=("PRIVESC: root LaunchDaemon runs non-root-writable program: $TARGET ($PLIST)")
            fi
          fi
        fi
      fi
    done < <(find "$LAUNCH_DIR" -maxdepth 1 -name "*.plist" 2>/dev/null)
  fi
done

log "\n  Checking for studentd / known remote-management daemons:"
launchctl list 2>/dev/null | grep -i "student\|mdm\|remotemanagement" | while read -r LINE; do
  log "    ${YELLOW}[FOUND]${RESET} $LINE"
done

# ============================================================
# [9] OTHER PERSISTENCE & STARTUP (beyond launchd)
# ============================================================
section "OTHER PERSISTENCE & STARTUP (login items, cron, hooks, legacy)"

log "  ${BOLD}Login items (System Events):${RESET}"
LOGIN_ITEMS=$(as_user osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
if [ -n "$LOGIN_ITEMS" ]; then
  echo "$LOGIN_ITEMS" | tr ',' '\n' | sed 's/^ *//' | while read -r ITEM; do
    [ -n "$ITEM" ] && log "    ${YELLOW}[LOGIN ITEM]${RESET} $ITEM"
  done
  note_mod "Login items: $LOGIN_ITEMS"
else
  log "    None visible. (Either none configured, or Terminal lacks Automation permission"
  log "    for System Events. Authoritative list incl. background items: 'sudo sfltool dumpbtm'.)"
fi

# Login/Logout hooks: legacy mechanism, still honored by loginwindow. Nothing
# modern installs these — anything here is either very old or persistence.
log "\n  ${BOLD}Login/Logout hooks (legacy, should be empty):${RESET}"
# FIX: hooks are written with `sudo defaults write com.apple.loginwindow`,
# i.e. into ROOT's preferences (/var/root/Library/Preferences) — the old
# check read the invoking user's domain and could never see them. Read the
# plist files directly (root's needs sudo; /Library's is world-readable).
LHOOK=""; LOHOOK=""
for LWP in /var/root/Library/Preferences/com.apple.loginwindow /Library/Preferences/com.apple.loginwindow "$HOME/Library/Preferences/com.apple.loginwindow"; do
  [ -z "$LHOOK" ]  && LHOOK=$(defaults read "$LWP" LoginHook 2>/dev/null)
  [ -z "$LOHOOK" ] && LOHOOK=$(defaults read "$LWP" LogoutHook 2>/dev/null)
done
[ "$IS_ROOT" = false ] && [ -z "$LHOOK$LOHOOK" ] && log "    (root's loginwindow prefs are only readable under sudo)"
if [ -n "$LHOOK" ] || [ -n "$LOHOOK" ]; then
  [ -n "$LHOOK" ]  && log "    ${RED}[FOUND]${RESET} LoginHook  → $LHOOK"
  [ -n "$LOHOOK" ] && log "    ${RED}[FOUND]${RESET} LogoutHook → $LOHOOK"
  REVIEW_ONLY+=("Login/Logout hook set (legacy persistence mechanism): ${LHOOK:-}${LHOOK:+ }${LOHOOK:-}")
else
  log "    None set (expected)."
fi

log "\n  ${BOLD}Cron / at jobs (rare on modern macOS — anything here is a deliberate add or persistence):${RESET}"
USER_CRON=$(as_user crontab -l 2>/dev/null | grep -vE '^\s*#|^\s*$')
if [ -n "$USER_CRON" ]; then
  echo "$USER_CRON" | while read -r LINE; do log "    ${YELLOW}[CRON]${RESET} $LINE"; done
  note_mod "User crontab has $(echo "$USER_CRON" | wc -l | tr -d ' ') entr(y/ies)"
else
  log "    User crontab: empty (expected)."
fi
[ -f /etc/crontab ] && { log "    ${RED}[FOUND]${RESET} /etc/crontab exists — not present on a factory install."; REVIEW_ONLY+=("/etc/crontab exists (non-factory)"); }
AT_JOBS=$(atq 2>/dev/null)
if [ -n "$AT_JOBS" ]; then
  log "    ${RED}[AT JOBS]${RESET} at-queue is non-empty (at is disabled by default on macOS):"
  echo "$AT_JOBS" | while read -r LINE; do log "      $LINE"; done
  REVIEW_ONLY+=("Non-empty at queue (at is off by default on macOS)")
else
  log "    at queue: empty (expected)."
fi

log "\n  ${BOLD}Legacy startup locations (deprecated — should not exist / be empty):${RESET}"
for LEGACY in "/etc/launchd.conf" "/etc/rc.local"; do
  if [ -e "$LEGACY" ]; then
    log "    ${RED}[FOUND]${RESET} $LEGACY — removed from macOS years ago; its presence is a deliberate add or persistence."
    REVIEW_ONLY+=("Legacy startup file present: $LEGACY")
  fi
done
for SI_DIR in "/Library/StartupItems"; do
  if [ -d "$SI_DIR" ] && [ -n "$(ls -A "$SI_DIR" 2>/dev/null)" ]; then
    log "    ${RED}[FOUND]${RESET} $SI_DIR is non-empty (StartupItems are deprecated):"
    ls -A "$SI_DIR" 2>/dev/null | while read -r I; do log "      $I"; done
    REVIEW_ONLY+=("Non-empty legacy StartupItems dir: $SI_DIR")
  fi
done
# emond (Event Monitor) — historical persistence vector (MITRE T1546.014).
# Removed entirely in recent macOS; if the rules dir exists, anything beyond
# Apple's SampleRules is suspect.
if [ -d /etc/emond.d/rules ]; then
  EMOND_EXTRA=$(ls -A /etc/emond.d/rules 2>/dev/null | grep -v "^SampleRules.plist$")
  if [ -n "$EMOND_EXTRA" ]; then
    log "    ${RED}[FOUND]${RESET} Non-sample emond rules (legacy persistence vector):"
    echo "$EMOND_EXTRA" | while read -r I; do log "      /etc/emond.d/rules/$I"; done
    REVIEW_ONLY+=("Non-sample emond rules present")
  fi
fi

# periodic(8) runs these as ROOT daily/weekly/monthly. Factory set below;
# any extra script, or any *.local file, is root persistence.
log "\n  ${BOLD}periodic scripts (run as root):${RESET}"
PERIODIC_FOUND=false
PERIODIC_FACTORY=" daily/110.clean-tmps daily/130.clean-msgs daily/140.clean-rwho daily/199.rotate-fax daily/310.accounting daily/400.status-disks daily/420.status-network daily/430.status-rwho daily/999.local weekly/320.whatis weekly/999.local monthly/199.rotate-fax monthly/200.accounting monthly/999.local "
for PD in daily weekly monthly; do
  for PF in /etc/periodic/$PD/*; do
    [ -e "$PF" ] || continue
    case "$PERIODIC_FACTORY" in *" $PD/$(basename "$PF") "*) continue ;; esac
    PERIODIC_FOUND=true
    log "    ${RED}[EXTRA]${RESET} $PF — not in the factory periodic set (owner $(stat -f %Su "$PF" 2>/dev/null))"
    REVIEW_ONLY+=("Non-factory periodic script (runs as root): $PF")
  done
done
for PL in /etc/daily.local /etc/weekly.local /etc/monthly.local /etc/periodic.conf /etc/periodic.conf.local /usr/local/etc/periodic; do
  if [ -e "$PL" ]; then
    PERIODIC_FOUND=true
    log "    ${RED}[FOUND]${RESET} $PL — local periodic hook, executed as root"
    REVIEW_ONLY+=("Periodic local hook present (runs as root): $PL")
  fi
done
[ "$PERIODIC_FOUND" = false ] && log "    Factory set only."

# Authorization plugins load into SecurityAgent/authd at login and see the
# password in clear (MITRE T1547.002). Apple's live in /System; this dir is
# empty on a factory install.
log "\n  ${BOLD}Authorization plugins (/Library/Security/SecurityAgentPlugins):${RESET}"
AUTHPLUG=$(ls -A /Library/Security/SecurityAgentPlugins 2>/dev/null | grep -v '^\.DS_Store$')
if [ -n "$AUTHPLUG" ]; then
  while IFS= read -r AP; do
    log "    ${RED}[AUTH PLUGIN]${RESET} $AP — $(sig_status "/Library/Security/SecurityAgentPlugins/$AP")"
    REVIEW_ONLY+=("Authorization plugin installed (sees login passwords): /Library/Security/SecurityAgentPlugins/$AP")
  done <<< "$AUTHPLUG"
else
  log "    None (factory)."
fi

# Directory-service and PAM plug-ins are another credential-interception spot.
DSPLUG=$(ls -A /Library/DirectoryServices/PlugIns 2>/dev/null | grep -v '^\.DS_Store$')
if [ -n "$DSPLUG" ]; then
  echo "$DSPLUG" | while IFS= read -r DP; do log "    ${YELLOW}[DS PLUGIN]${RESET} /Library/DirectoryServices/PlugIns/$DP"; done
  note_mod "DirectoryServices plug-ins: $(echo "$DSPLUG" | tr '\n' ' ')"
fi
PAM_EXTRA=$(ls -A /usr/local/lib/pam /opt/homebrew/lib/pam 2>/dev/null | grep -v ':$' | grep -v '^$')
if [ -n "$PAM_EXTRA" ]; then
  log "    ${YELLOW}[PAM MODULES]${RESET} third-party PAM modules present: $(echo "$PAM_EXTRA" | tr '\n' ' ')"
  note_mod "Third-party PAM modules: $(echo "$PAM_EXTRA" | tr '\n' ' ')"
fi

# Root-only: authoritative background-item database and every crontab.
if [ "$IS_ROOT" = true ]; then
  log "\n  ${BOLD}Background Task Management (sfltool dumpbtm — non-Apple items):${RESET}"
  BTM=$(sfltool dumpbtm 2>/dev/null | awk '
    function flush() { if (id != "" && id !~ /^com\.apple\./ && tm != "Apple") printf "%s | %s | %s | %s | %s\n", (nm==""?"?":nm), id, ty, dp, (ex==""?url:ex); nm=id=ty=dp=ex=url=tm="" }
    /^ *#[0-9]+:/ { flush(); next }
    /^ +Name: /            { sub(/^ +Name: /,"");            nm=$0 }
    /^ +Identifier: /      { sub(/^ +Identifier: /,"");      id=$0 }
    /^ +Type: /            { sub(/^ +Type: /,"");            ty=$0 }
    /^ +Disposition: /     { sub(/^ +Disposition: /,"");     dp=$0 }
    /^ +Executable Path: / { sub(/^ +Executable Path: /,""); ex=$0 }
    /^ +URL: /             { sub(/^ +URL: /,"");             url=$0 }
    /^ +Developer Name: /  { sub(/^ +Developer Name: /,"");  if ($0 ~ /^Apple/) tm="Apple" }
    END { flush() }' | sort -u)
  if [ -n "$BTM" ]; then
    echo "$BTM" | while IFS= read -r LINE; do log "    $LINE"; done
    note_mod "$(echo "$BTM" | wc -l | tr -d ' ') non-Apple background items registered (sfltool dumpbtm)"
  else
    log "    None parsed (or sfltool output format changed — run 'sudo sfltool dumpbtm' manually)."
  fi

  log "\n  ${BOLD}All crontabs (/usr/lib/cron/tabs):${RESET}"
  CRONTABS=$(ls -A /usr/lib/cron/tabs 2>/dev/null)
  if [ -n "$CRONTABS" ]; then
    while IFS= read -r CU; do
      log "    ${YELLOW}[CRONTAB]${RESET} $CU:"
      grep -vE '^\s*#|^\s*$' "/usr/lib/cron/tabs/$CU" 2>/dev/null | while IFS= read -r LINE; do log "      $LINE"; done
      [ "$CU" = "root" ] && REVIEW_ONLY+=("root crontab present")
    done <<< "$CRONTABS"
  else
    log "    None."
  fi
fi

log "    (LaunchAgents/Daemons are covered in section 8.)"

# ============================================================
# [10] SYSTEM MODIFICATIONS (/etc, kexts, profiles, users, CAs)
# ============================================================
section "SYSTEM MODIFICATIONS (/etc, sudo, shell/PATH, kernel/system extensions, profiles, trust)"

log "  ${BOLD}/etc/hosts — entries beyond the factory three:${RESET}"
EXTRA_HOSTS=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null | \
  grep -vE '^(127\.0\.0\.1[[:space:]]+localhost|255\.255\.255\.255[[:space:]]+broadcasthost|::1[[:space:]]+localhost)[[:space:]]*$')
if [ -n "$EXTRA_HOSTS" ]; then
  echo "$EXTRA_HOSTS" | while read -r LINE; do log "    ${YELLOW}[MODIFIED]${RESET} $LINE"; done
  note_mod "/etc/hosts has $(echo "$EXTRA_HOSTS" | wc -l | tr -d ' ') non-factory entr(y/ies)"
else
  log "    Factory default (no custom entries)."
fi

log "\n  ${BOLD}sudo & PAM modifications:${RESET}"
SUDOERS_D=$(ls -A /etc/sudoers.d 2>/dev/null)
if [ -n "$SUDOERS_D" ]; then
  echo "$SUDOERS_D" | while read -r F; do log "    ${YELLOW}[SUDOERS.D]${RESET} /etc/sudoers.d/$F (contents readable only via 'sudo visudo -cf')"; done
  note_mod "Custom sudoers drop-ins: $(echo "$SUDOERS_D" | tr '\n' ' ')"
else
  log "    /etc/sudoers.d: empty (factory default)."
fi
if [ -f /etc/pam.d/sudo_local ]; then
  if grep -q "^[^#]*pam_tid" /etc/pam.d/sudo_local 2>/dev/null; then
    log "    ${YELLOW}[MODIFIED]${RESET} /etc/pam.d/sudo_local — Touch ID for sudo enabled (common deliberate mod)."
    note_mod "Touch ID for sudo enabled (/etc/pam.d/sudo_local)"
  else
    log "    ${YELLOW}[MODIFIED]${RESET} /etc/pam.d/sudo_local exists with non-default content — review:"
    grep -vE '^\s*#|^\s*$' /etc/pam.d/sudo_local 2>/dev/null | while read -r LINE; do log "      $LINE"; done
    REVIEW_ONLY+=("/etc/pam.d/sudo_local has non-standard content")
  fi
fi

if [ "$IS_ROOT" = true ]; then
  # NOPASSWD / !authenticate = anything running as you gets root silently.
  SUDO_RULES=$(grep -hvE '^\s*#|^\s*$|^\s*Defaults|^\s*@?#?include' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | \
    grep -vE '^\s*root\s+ALL\s*=\s*\(ALL\)\s*ALL\s*$|^\s*%admin\s+ALL\s*=\s*\(ALL\)\s*ALL\s*$')
  if [ -n "$SUDO_RULES" ]; then
    log "    ${YELLOW}[SUDOERS]${RESET} non-factory rules:"
    echo "$SUDO_RULES" | while IFS= read -r LINE; do log "      $LINE"; done
    note_mod "Non-factory sudoers rules present"
  else
    log "    sudoers rules: factory (root + %admin only)."
  fi
  if echo "$SUDO_RULES" | grep -qE 'NOPASSWD|!authenticate'; then
    log "    ${RED}[NOPASSWD]${RESET} passwordless sudo rule present — any process running as that user can become root."
    REVIEW_ONLY+=("Passwordless sudo rule (NOPASSWD/!authenticate) in sudoers")
  fi
else
  log "    (sudoers rules readable only under sudo)"
fi

log "\n  ${BOLD}Other /etc modifications:${RESET}"
ETC_MOD_FOUND=false
if [ -s /etc/synthetic.conf ]; then
  ETC_MOD_FOUND=true
  log "    ${YELLOW}[MODIFIED]${RESET} /etc/synthetic.conf (root-level symlinks/dirs):"
  grep -vE '^\s*#|^\s*$' /etc/synthetic.conf 2>/dev/null | while read -r LINE; do log "      $LINE"; done
  note_mod "/etc/synthetic.conf present"
fi
if [ -s /etc/fstab ]; then
  ETC_MOD_FOUND=true
  log "    ${YELLOW}[MODIFIED]${RESET} /etc/fstab (custom mount rules):"
  grep -vE '^\s*#|^\s*$' /etc/fstab 2>/dev/null | while read -r LINE; do log "      $LINE"; done
  note_mod "/etc/fstab present"
fi
if [ -d /etc/resolver ] && [ -n "$(ls -A /etc/resolver 2>/dev/null)" ]; then
  ETC_MOD_FOUND=true
  log "    ${YELLOW}[MODIFIED]${RESET} /etc/resolver/ custom DNS resolvers:"
  ls -A /etc/resolver 2>/dev/null | while read -r F; do log "      $F → $(grep -v '^#' "/etc/resolver/$F" 2>/dev/null | tr '\n' ' ')"; done
  note_mod "Custom /etc/resolver entries: $(ls -A /etc/resolver 2>/dev/null | tr '\n' ' ')"
fi
SSHD_D_EXTRA=$(ls -A /etc/ssh/sshd_config.d 2>/dev/null | grep -v "^100-macos.conf$")
if [ -n "$SSHD_D_EXTRA" ]; then
  ETC_MOD_FOUND=true
  echo "$SSHD_D_EXTRA" | while read -r F; do log "    ${YELLOW}[MODIFIED]${RESET} /etc/ssh/sshd_config.d/$F (custom sshd config)"; done
  note_mod "Custom sshd config drop-ins: $(echo "$SSHD_D_EXTRA" | tr '\n' ' ')"
fi
[ "$ETC_MOD_FOUND" = false ] && log "    None found (synthetic.conf, fstab, resolver/, sshd_config.d all factory)."

log "\n  ${BOLD}Third-party kernel extensions (/Library/Extensions + loaded):${RESET}"
KEXT_FOUND=false
if [ -d /Library/Extensions ] && [ -n "$(ls -A /Library/Extensions 2>/dev/null)" ]; then
  KEXT_FOUND=true
  ls -A /Library/Extensions 2>/dev/null | while read -r K; do log "    ${YELLOW}[KEXT INSTALLED]${RESET} /Library/Extensions/$K"; done
  note_mod "Third-party kexts in /Library/Extensions: $(ls -A /Library/Extensions 2>/dev/null | tr '\n' ' ')"
fi
LOADED_KEXTS=$(kmutil showloaded --list-only 2>/dev/null | grep -v "com\.apple\." | grep -vE '^\s*$|^No |^Executing')
if [ -n "$LOADED_KEXTS" ]; then
  KEXT_FOUND=true
  echo "$LOADED_KEXTS" | while read -r LINE; do log "    ${RED}[KEXT LOADED]${RESET} $LINE"; done
  note_mod "Non-Apple kernel extensions currently loaded (see section 10)"
fi
[ "$KEXT_FOUND" = false ] && log "    None found (expected on a modern Mac — kexts are all but gone)."

log "\n  ${BOLD}System extensions (network filters, EDR, drivers):${RESET}"
SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -vE '^---|^enabled|extension\(s\)|^\s*$' | grep -v "com\.apple\.")
if [ -n "$SYSEXT" ]; then
  echo "$SYSEXT" | while read -r LINE; do log "    ${YELLOW}[SYSEXT]${RESET} $LINE"; done
  note_mod "Third-party system extensions present (see section 10)"
else
  log "    None (or none beyond Apple's)."
fi

log "\n  ${BOLD}Configuration profiles (MDM / settings payloads):${RESET}"
PROFILES_OUT=$(profiles list 2>/dev/null | grep -vE '^There are no|^\s*$')
if [ -n "$PROFILES_OUT" ]; then
  echo "$PROFILES_OUT" | while read -r LINE; do log "    ${YELLOW}[PROFILE]${RESET} $LINE"; done
  note_mod "Configuration profiles installed (see section 10)"
else
  log "    None$([ "$IS_ROOT" = false ] && echo " at user level. (System-level check needs sudo.)")"
fi
ENROLL=$(profiles status -type enrollment 2>/dev/null)
if echo "$ENROLL" | grep -qi "MDM enrollment: Yes"; then
  log "    ${YELLOW}[MDM]${RESET} $(echo "$ENROLL" | tr '\n' ' ')"
  REVIEW_ONLY+=("Mac is MDM-enrolled — an organisation can push profiles/software; verify it's expected")
fi

log "\n  ${BOLD}Custom certificate trust settings (MITM proxies, corp CAs):${RESET}"
TRUST_USER=$(as_user security dump-trust-settings 2>/dev/null | grep -c "Cert " || true)
TRUST_ADMIN=$(security dump-trust-settings -d 2>/dev/null | grep -c "Cert " || true)
if [ "${TRUST_USER:-0}" -gt 0 ] || [ "${TRUST_ADMIN:-0}" -gt 0 ]; then
  log "    ${YELLOW}[MODIFIED]${RESET} Custom trust settings: ${TRUST_USER:-0} user-domain, ${TRUST_ADMIN:-0} admin-domain cert(s)."
  as_user security dump-trust-settings 2>/dev/null | grep "Cert " | while read -r LINE; do log "      [user]  $LINE"; done
  security dump-trust-settings -d 2>/dev/null | grep "Cert " | while read -r LINE; do log "      [admin] $LINE"; done
  note_mod "Custom certificate trust settings (${TRUST_USER:-0} user / ${TRUST_ADMIN:-0} admin)"
else
  log "    None — trust store is factory."
fi

log "\n  ${BOLD}Shell startup files (~/.zshrc etc.) — existence + injected-command scan:${RESET}"
for RC in .zshrc .zprofile .zshenv .zlogin .bashrc .bash_profile .profile; do
  RCF="$HOME/$RC"
  [ -f "$RCF" ] || continue
  LINES=$(grep -cvE '^\s*#|^\s*$' "$RCF" 2>/dev/null)
  MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d" "$RCF" 2>/dev/null)
  log "    ~/$RC — ${LINES:-0} effective lines, modified $MODIFIED"
  # Red flags: pipe-a-download-to-shell, base64-decoded eval, dylib injection.
  SUS=$(grep -nE "$SUS_RC_RE" "$RCF" 2>/dev/null)
  if [ -n "$SUS" ]; then
    echo "$SUS" | while read -r LINE; do log "      ${RED}[SUSPICIOUS]${RESET} $LINE"; done
    REVIEW_ONLY+=("Suspicious line(s) in ~/$RC — pipe-to-shell / base64-eval / dylib injection pattern")
  fi
done

# System-wide startup files run for EVERY user's shell. /etc/zshenv runs
# even for non-interactive zsh (scripts, cron) — prime injection point.
log "\n  ${BOLD}System-wide shell startup files (/etc):${RESET}"
for RC in /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/zlogout /etc/profile /etc/bashrc; do
  [ -f "$RC" ] || continue
  MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d" "$RC" 2>/dev/null)
  case "$RC" in
    /etc/zshenv|/etc/zlogin|/etc/zlogout)
      log "    ${YELLOW}[NON-FACTORY]${RESET} $RC exists (not shipped by Apple), modified $MODIFIED"
      note_mod "$RC exists (system-wide shell startup, not factory)" ;;
    *) log "    $RC — modified $MODIFIED" ;;
  esac
  SUS=$(grep -nE "$SUS_RC_RE" "$RC" 2>/dev/null)
  if [ -n "$SUS" ]; then
    echo "$SUS" | while IFS= read -r LINE; do log "      ${RED}[SUSPICIOUS]${RESET} $LINE"; done
    REVIEW_ONLY+=("Suspicious line(s) in $RC (applies to all users)")
  fi
done
PATHS_D=$(ls -A /etc/paths.d 2>/dev/null)
[ -n "$PATHS_D" ] && log "    /etc/paths.d: $(echo "$PATHS_D" | tr '\n' ' ')"

# PATH hijack: a writable dir ahead of /usr/bin lets anything drop a fake
# `sudo`/`ls`/`git` that runs next time you type it.
log "\n  ${BOLD}PATH order & writability (dirs searched before /usr/bin):${RESET}"
AUDIT_PATH=$(as_user /bin/zsh -lc 'echo $PATH' </dev/null 2>/dev/null | tail -1)
[ -z "$AUDIT_PATH" ] && AUDIT_PATH="$PATH"
PATH_ISSUE=false
OLDIFS="$IFS"; IFS=':'
for PD in $AUDIT_PATH; do
  [ "$PD" = "/usr/bin" ] && break
  if [ -z "$PD" ] || [ "$PD" = "." ]; then
    log "    ${RED}[PATH]${RESET} empty or '.' entry — current directory is searched before system binaries"
    REVIEW_ONLY+=("PATH contains '.' or an empty entry before /usr/bin"); PATH_ISSUE=true; continue
  fi
  [ -d "$PD" ] || continue
  PMODE=$(perm_of "$PD"); PMODE=${PMODE:-0}
  if [ $(( 8#$PMODE & 2 )) -ne 0 ]; then
    log "    ${RED}[PATH]${RESET} $PD is WORLD-writable and searched before /usr/bin"
    REVIEW_ONLY+=("World-writable PATH dir ahead of /usr/bin: $PD"); PATH_ISSUE=true
  elif [ "$(stat -f %Su "$PD" 2>/dev/null)" != "root" ]; then
    log "    $PD — owned by $(stat -f %Su "$PD" 2>/dev/null) (normal for Homebrew/user bins; anything running as you can shadow commands here)"
  fi
done
IFS="$OLDIFS"
[ "$PATH_ISSUE" = false ] && log "    No world-writable or '.' entries ahead of /usr/bin."

log "\n  ${BOLD}/usr/local & /opt (everything here is non-factory by definition):${RESET}"
for D in /usr/local /opt; do
  if [ -d "$D" ] && [ -n "$(ls -A "$D" 2>/dev/null)" ]; then
    log "    $D: $(ls -A "$D" 2>/dev/null | tr '\n' ' ')"
  else
    log "    $D: empty or absent."
  fi
done
log "    (Homebrew owns /opt/homebrew on Apple Silicon, /usr/local on Intel — its presence there is expected.)"

# ============================================================
# [11] ROOT & PRIVILEGE SURFACE (added 2026-09)
# ============================================================
section "ROOT & PRIVILEGE SURFACE (/, SUID, privileged helpers, writable system paths)"

# The root of the boot volume is a merged view of the sealed System volume
# and firmlinks/synthetic entries. Anything beyond this set was added.
log "  ${BOLD}Top level of / (non-factory entries):${RESET}"
ROOT_FACTORY=" Applications Library System Users Volumes bin cores dev etc home opt private sbin tmp usr var .file .vol .VolumeIcon.icns .nofollow .resolve .DS_Store .Spotlight-V100 .fseventsd .Trashes .DocumentRevisions-V100 .PKInstallSandboxManager-SystemSoftware .TemporaryItems .com.apple.templatemigration.boot-install "
ROOT_EXTRA_FOUND=false
while IFS= read -r RE; do
  [ -z "$RE" ] && continue
  case "$ROOT_FACTORY" in *" $RE "*) continue ;; esac
  ROOT_EXTRA_FOUND=true
  RP="/$RE"
  KIND="dir"; [ -L "$RP" ] && KIND="symlink → $(readlink "$RP")"; [ -f "$RP" ] && KIND="file"
  log "    ${YELLOW}[NON-FACTORY]${RESET} $RP ($KIND, owner $(stat -f %Su "$RP" 2>/dev/null))"
  if [ -f "$RP" ] && [ -x "$RP" ]; then
    REVIEW_ONLY+=("Executable file at filesystem root: $RP")
  else
    ROOT_EXTRA_LIST="${ROOT_EXTRA_LIST:-}$RP "
  fi
done < <(ls -A / 2>/dev/null)
[ -n "${ROOT_EXTRA_LIST:-}" ] && note_mod "Non-factory entries at /: $ROOT_EXTRA_LIST"
[ "$ROOT_EXTRA_FOUND" = false ] && log "    None (only factory entries and firmlinks)."
[ -d /opt ] && log "    (/opt itself is non-factory but expected with Homebrew on Apple Silicon.)"

# SUID/SGID outside SIP-protected paths: any such binary is a root (or
# group) escalation primitive that Apple did not ship.
log "\n  ${BOLD}SUID/SGID binaries outside SIP-protected paths:${RESET}"
SUID_COUNT=0
while IFS= read -r SF; do
  [ -z "$SF" ] && continue
  SUID_COUNT=$((SUID_COUNT + 1))
  [ "$SUID_COUNT" -gt 40 ] && continue
  SOWN=$(stat -f "%Su:%Sg %Sp" "$SF" 2>/dev/null)
  SSIG=$(sig_status "$SF")
  log "    ${YELLOW}[SUID/SGID]${RESET} $SF — $SOWN — $SSIG"
  if [ "$SSIG" = "UNSIGNED" ] || [ "$SSIG" = "ad-hoc" ] || suspicious_location "$SF"; then
    REVIEW_ONLY+=("SUID/SGID binary, unsigned/ad-hoc or in odd location: $SF ($SOWN)")
  else
    note_mod "Signed SUID/SGID binary outside system paths: $SF"
  fi
done < <(
  find /usr/local /opt /Library /Applications /Users/Shared /private/tmp /private/var/tmp -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
  find "$HOME" -xdev -maxdepth 4 \( -path "$HOME/Library" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
)
[ "$SUID_COUNT" -gt 40 ] && log "    … $((SUID_COUNT - 40)) more not shown."
[ "$SUID_COUNT" -eq 0 ] && log "    None (expected)."

# Privileged helper tools run as root on demand (SMJobBless). They are
# left behind when the owning app is dragged to the Trash.
log "\n  ${BOLD}Privileged helper tools (/Library/PrivilegedHelperTools — run as root):${RESET}"
PHT_FOUND=false
DAEMON_DUMP=$(for P in /Library/LaunchDaemons/*.plist; do [ -f "$P" ] && plutil -p "$P" 2>/dev/null; done)
while IFS= read -r PH; do
  [ -z "$PH" ] && continue
  PHT_FOUND=true
  PHP="/Library/PrivilegedHelperTools/$PH"
  PSIG=$(sig_status "$PHP")
  STATE="registered"
  echo "$DAEMON_DUMP" | grep -qF "$PHP" || STATE="ORPHANED (no LaunchDaemon references it — owning app likely removed)"
  log "    $PH — $PSIG — $STATE"
  case "$STATE" in ORPHANED*) REVIEW_ONLY+=("Orphaned root helper (leftover of an uninstalled app?): $PHP") ;; esac
  [ "$PSIG" = "UNSIGNED" ] && REVIEW_ONLY+=("Unsigned privileged helper tool: $PHP")
  if writable_by_nonroot "$PHP"; then
    log "      ${RED}[PRIVESC]${RESET} writable by non-root ($(stat -f '%Su:%Sg %Sp' "$PHP" 2>/dev/null))"
    REVIEW_ONLY+=("PRIVESC: privileged helper writable by non-root: $PHP")
  fi
done < <(ls -A /Library/PrivilegedHelperTools 2>/dev/null | grep -v '^\.DS_Store$')
[ "$PHT_FOUND" = false ] && log "    None."
[ "$PHT_FOUND" = true ] && note_mod "Privileged helper tools installed: $(ls -A /Library/PrivilegedHelperTools 2>/dev/null | grep -v '^\.DS_Store$' | tr '\n' ' ')"

# World-writable (non-sticky) files/dirs under system-wide paths: root
# processes that read or execute from them can be hijacked by any user.
log "\n  ${BOLD}World-writable files/dirs in /Library, /usr/local, /opt (non-sticky):${RESET}"
WW=$(find /Library /usr/local /opt -xdev \( -type f -o -type d \) -perm -0002 ! -perm -1000 2>/dev/null)
if [ -n "$WW" ]; then
  WW_N=$(echo "$WW" | wc -l | tr -d ' ')
  echo "$WW" | head -25 | while IFS= read -r LINE; do log "    ${RED}[WORLD-WRITABLE]${RESET} $LINE"; done
  [ "$WW_N" -gt 25 ] && log "    … $((WW_N - 25)) more."
  REVIEW_ONLY+=("$WW_N world-writable path(s) under /Library, /usr/local, /opt (see section 11)")
else
  log "    None."
fi

if [ "$IS_ROOT" = true ]; then
  log "\n  ${BOLD}/var/root (root's home):${RESET}"
  VR_ITEMS=$(ls -A /var/root 2>/dev/null | grep -vE '^(\.CFUserTextEncoding|Library|\.forward|\.DS_Store)$')
  if [ -n "$VR_ITEMS" ]; then
    log "    Non-default items: $(echo "$VR_ITEMS" | tr '\n' ' ')"
    note_mod "/var/root contains: $(echo "$VR_ITEMS" | tr '\n' ' ')"
  else
    log "    Factory (no dotfiles beyond defaults)."
  fi
  for RC in .zshrc .zshenv .zprofile .bashrc .bash_profile .profile; do
    [ -f "/var/root/$RC" ] || continue
    SUS=$(grep -nE "$SUS_RC_RE" "/var/root/$RC" 2>/dev/null)
    if [ -n "$SUS" ]; then
      echo "$SUS" | while IFS= read -r LINE; do log "      ${RED}[SUSPICIOUS]${RESET} /var/root/$RC: $LINE"; done
      REVIEW_ONLY+=("Suspicious line(s) in root's /var/root/$RC")
    fi
  done
  if [ -s /var/root/.ssh/authorized_keys ]; then
    log "    ${RED}[ROOT SSH KEYS]${RESET} /var/root/.ssh/authorized_keys:"
    ssh-keygen -lf /var/root/.ssh/authorized_keys 2>/dev/null | while IFS= read -r LINE; do log "      $LINE"; done
    REVIEW_ONLY+=("root has SSH authorized_keys (/var/root/.ssh/authorized_keys)")
  fi
else
  log "\n  (/var/root is readable only under sudo.)"
fi

# ============================================================
# [12] USER ACCOUNTS & HOME (added 2026-09)
# ============================================================
section "USER ACCOUNTS & HOME (accounts, logins, SSH, credentials, ownership)"

log "  ${BOLD}Local user accounts (UID >= 500) & admin group:${RESET}"
dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500' | while read -r U UID_; do
  log "    [USER] $U (uid $UID_, shell $(dscl . -read "/Users/$U" UserShell 2>/dev/null | awk '{print $2}'))"
done
HIDDEN_USERS=$(dscl . -list /Users IsHidden 2>/dev/null | awk '$2 == 1 {print $1}')
if [ -n "$HIDDEN_USERS" ]; then
  echo "$HIDDEN_USERS" | while read -r U; do
    log "    ${RED}[HIDDEN USER]${RESET} $U — hidden accounts are a classic persistence trick; verify you created this."
  done
  REVIEW_ONLY+=("Hidden user account(s): $(echo "$HIDDEN_USERS" | tr '\n' ' ')")
fi
ADMIN_MEMBERS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: //')
log "    Admin group members: ${ADMIN_MEMBERS:-unreadable}"

# UID 0 = root, whatever the name. A second UID-0 account is a backdoor.
UID0=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 == 0 && $1 != "root" {print $1}')
if [ -n "$UID0" ]; then
  log "    ${RED}[UID 0 CLONE]${RESET} account(s) with root's UID: $UID0"
  REVIEW_ONLY+=("Non-root account(s) with UID 0 (root clone / backdoor): $UID0")
fi
# System-range accounts (UID < 500) that are NOT Apple's _service accounts
# but can log in (real shell) — nothing Apple ships looks like this.
# (Plain loop, not $(… case …): bash 3.2 mis-parses `case` patterns inside $().)
SYS_SHELL=""
while read -r U; do
  case "$U" in _*|root|daemon|nobody) continue ;; esac
  SH=$(dscl . -read "/Users/$U" UserShell 2>/dev/null | awk '{print $2}')
  case "$SH" in ""|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin) ;; *) SYS_SHELL="$SYS_SHELL $U($SH)" ;; esac
done < <(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 < 500 {print $1}')
SYS_SHELL="${SYS_SHELL# }"
if [ -n "$SYS_SHELL" ]; then
  log "    ${RED}[SYSTEM-RANGE LOGIN]${RESET} UID<500 account(s) with a login shell: $SYS_SHELL"
  REVIEW_ONLY+=("UID<500 non-service account(s) with login shell: $SYS_SHELL")
fi

log "\n  ${BOLD}Remote logins in wtmp (last 200 sessions):${RESET}"
REMOTE_LOGINS=$(last -200 2>/dev/null | awk '$2 ~ /^ttys/ && $3 ~ /[.:]/ {print $1" from "$3}' | sort | uniq -c | sort -rn)
if [ -n "$REMOTE_LOGINS" ]; then
  echo "$REMOTE_LOGINS" | while IFS= read -r LINE; do log "    ${YELLOW}[REMOTE]${RESET} $LINE session(s)"; done
  note_mod "Remote (SSH) logins recorded — verify every source host (section 12)"
else
  log "    None recorded."
fi

log "\n  ${BOLD}Home directory permissions:${RESET}"
HMODE=$(perm_of "$HOME"); HMODE=${HMODE:-0}
log "    $HOME — $(stat -f '%Su:%Sg %Sp' "$HOME" 2>/dev/null)"
if [ $(( 8#$HMODE & 7 )) -ne 0 ]; then
  log "    ${RED}Home is accessible to all users (other bits set). Default is 750/700.${RESET}"
  REVIEW_ONLY+=("Home directory $HOME has world permissions ($HMODE)")
fi

# ---- SSH ----
log "\n  ${BOLD}SSH (keys that grant access IN, keys that grant access OUT):${RESET}"
SSH_HOMES="$HOME"
if [ "$IS_ROOT" = true ]; then
  for UH in /Users/*; do [ "$UH" != "$HOME" ] && [ -d "$UH/.ssh" ] && SSH_HOMES="$SSH_HOMES
$UH"; done
fi
while IFS= read -r SH_HOME; do
  [ -d "$SH_HOME/.ssh" ] || continue
  SMODE=$(perm_of "$SH_HOME/.ssh")
  log "    $SH_HOME/.ssh (mode $SMODE)"
  [ $(( 8#${SMODE:-0} & 077 )) -ne 0 ] && REVIEW_ONLY+=("$SH_HOME/.ssh is group/world accessible ($SMODE)")
  AK="$SH_HOME/.ssh/authorized_keys"
  if [ -s "$AK" ]; then
    AKN=$(grep -cvE '^\s*#|^\s*$' "$AK" 2>/dev/null)
    log "      ${YELLOW}[AUTHORIZED_KEYS]${RESET} $AKN key(s) can log in as $(basename "$SH_HOME"):"
    ssh-keygen -lf "$AK" 2>/dev/null | while IFS= read -r LINE; do log "        $LINE"; done
    grep -qE '(^|,)command=' "$AK" 2>/dev/null && log "        (some keys carry forced command= options)"
    note_mod "$AKN authorized SSH key(s) for $(basename "$SH_HOME") — verify each fingerprint"
  fi
  for K in "$SH_HOME"/.ssh/*; do
    [ -f "$K" ] || continue
    head -1 "$K" 2>/dev/null | grep -q "PRIVATE KEY" || continue
    KMODE=$(perm_of "$K")
    ENC="passphrase-protected"
    ssh-keygen -y -P "" -f "$K" >/dev/null 2>&1 && ENC="NO PASSPHRASE"
    log "      [PRIVATE KEY] $(basename "$K") — mode $KMODE — $ENC"
    [ $(( 8#${KMODE:-0} & 077 )) -ne 0 ] && REVIEW_ONLY+=("SSH private key readable by others: $K ($KMODE)")
    [ "$ENC" = "NO PASSPHRASE" ] && note_mod "Unencrypted SSH private key: $K (anything running as you can copy and use it)"
  done
  if [ -f "$SH_HOME/.ssh/config" ]; then
    SSHCMD=$(grep -nEi '^\s*(ProxyCommand|LocalCommand|PermitLocalCommand\s+yes|KnownHostsCommand|Match\s+exec)' "$SH_HOME/.ssh/config" 2>/dev/null)
    if [ -n "$SSHCMD" ]; then
      echo "$SSHCMD" | while IFS= read -r LINE; do log "      [ssh config runs a command] $LINE"; done
      note_mod "~/.ssh/config executes local commands (ProxyCommand/LocalCommand/Match exec) — verify"
    fi
  fi
done <<< "$SSH_HOMES"

# ---- plaintext credential stores ----
log "\n  ${BOLD}Plaintext credential files (should be mode 600 or tighter):${RESET}"
CRED_FOUND=false
for CF in .aws/credentials .netrc .git-credentials .npmrc .pypirc .docker/config.json .config/gh/hosts.yml .kube/config .env .pgpass .my.cnf; do
  F="$HOME/$CF"
  [ -f "$F" ] || continue
  case "$CF" in
    .npmrc)             grep -q '_authToken\|_auth\s*=' "$F" 2>/dev/null || continue ;;
    .docker/config.json) grep -q '"auth"' "$F" 2>/dev/null || continue ;;
  esac
  CRED_FOUND=true
  CMODE=$(perm_of "$F")
  if [ $(( 8#${CMODE:-0} & 077 )) -ne 0 ]; then
    log "    ${RED}[EXPOSED]${RESET} ~/$CF — mode $CMODE (readable by group/others)"
    REVIEW_ONLY+=("Credential file readable by others: ~/$CF ($CMODE) — chmod 600")
  else
    log "    ~/$CF — mode $CMODE"
  fi
done
[ "$CRED_FOUND" = true ] && note_mod "Plaintext credential files present in home (section 12) — prime infostealer targets"
[ "$CRED_FOUND" = false ] && log "    None found."

# ---- ownership anomalies ----
# Root-owned files in your home come from `sudo pip/npm/brew` or installers;
# they can't be updated/removed by you and occasionally hide persistence.
log "\n  ${BOLD}Items in your home NOT owned by $TARGET_USER:${RESET}"
FOREIGN=$(
  find "$HOME" -xdev -maxdepth 3 -path "$HOME/Library" -prune -o ! -user "$TARGET_USER" -print 2>/dev/null
  find "$HOME/Library" "$HOME/Library/Application Support" "$HOME/Library/LaunchAgents" "$HOME/Library/Preferences" -maxdepth 1 ! -user "$TARGET_USER" 2>/dev/null
)
FOREIGN=$(echo "$FOREIGN" | grep -v '^$' | sort -u)
if [ -n "$FOREIGN" ]; then
  FN=$(echo "$FOREIGN" | wc -l | tr -d ' ')
  echo "$FOREIGN" | head -30 | while IFS= read -r FP; do log "    ${YELLOW}[FOREIGN]${RESET} $FP — $(stat -f '%Su:%Sg' "$FP" 2>/dev/null)"; done
  [ "$FN" -gt 30 ] && log "    … $((FN - 30)) more."
  REVIEW_ONLY+=("$FN item(s) in your home owned by another user (usually root) — see section 12")
else
  log "    None."
fi

if [ "$IS_ROOT" = true ]; then
  log "\n  ${BOLD}Other users' shell startup files:${RESET}"
  OTHER_RC=false
  for UH in /Users/*; do
    [ "$UH" = "$HOME" ] || [ "$UH" = "/Users/Shared" ] && continue
    [ -d "$UH" ] || continue
    for RC in .zshrc .zprofile .zshenv .zlogin .bashrc .bash_profile .profile; do
      [ -f "$UH/$RC" ] || continue
      OTHER_RC=true
      SUS=$(grep -nE "$SUS_RC_RE" "$UH/$RC" 2>/dev/null)
      if [ -n "$SUS" ]; then
        echo "$SUS" | while IFS= read -r LINE; do log "    ${RED}[SUSPICIOUS]${RESET} $UH/$RC: $LINE"; done
        REVIEW_ONLY+=("Suspicious line(s) in $UH/$RC")
      fi
    done
  done
  [ "$OTHER_RC" = false ] && log "    No other user homes with rc files."
fi

# ============================================================
# [13] APP EXTENSIONS & PLUG-INS
# ============================================================
section "APP EXTENSIONS & PLUG-INS (pluginkit, browsers, Library plug-in dirs)"

log "  ${BOLD}Third-party app extensions (pluginkit — Finder sync, share sheets, widgets):${RESET}"
PK_OUT=$(as_user pluginkit -m 2>/dev/null | grep -v "com\.apple\." | sort)
if [ -n "$PK_OUT" ]; then
  echo "$PK_OUT" | while read -r LINE; do log "    $LINE"; done
  note_mod "$(echo "$PK_OUT" | wc -l | tr -d ' ') third-party app extensions registered (pluginkit)"
else
  log "    None."
fi

log "\n  ${BOLD}Browser extensions:${RESET}"
# Chromium-family: Extensions/<id>/<version>/manifest.json under each profile.
BROWSER_NAMES=( "Chrome" "Brave" "Edge" "Arc" "Vivaldi" "Chromium" )
BROWSER_DIRS=(
  "Google/Chrome"
  "BraveSoftware/Brave-Browser"
  "Microsoft Edge"
  "Arc/User Data"
  "Vivaldi"
  "Chromium"
)
EXT_TOTAL=0
for IDX in "${!BROWSER_NAMES[@]}"; do
  BBASE="$HOME/Library/Application Support/${BROWSER_DIRS[$IDX]}"
  [ -d "$BBASE" ] || continue
  while IFS= read -r MF; do
    EXTDIR=$(dirname "$(dirname "$MF")")
    EXTID=$(basename "$EXTDIR")
    ENAME=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MF" 2>/dev/null | head -1)
    log "    [${BROWSER_NAMES[$IDX]}] ${ENAME:-unnamed} — $EXTID"
    EXT_TOTAL=$((EXT_TOTAL + 1))
  done < <(find "$BBASE" -maxdepth 6 -path "*/Extensions/*/manifest.json" 2>/dev/null)
done
# Firefox: extensions/<id>.xpi per profile.
if [ -d "$HOME/Library/Application Support/Firefox/Profiles" ]; then
  while IFS= read -r XPI; do
    log "    [Firefox] $(basename "$XPI" .xpi)"
    EXT_TOTAL=$((EXT_TOTAL + 1))
  done < <(find "$HOME/Library/Application Support/Firefox/Profiles" -maxdepth 3 -name "*.xpi" -path "*/extensions/*" 2>/dev/null)
fi
# Safari: extensions register through pluginkit.
SAFARI_EXT=$(as_user pluginkit -m -p com.apple.Safari.web-extension -p com.apple.Safari.extension 2>/dev/null | grep -v "com\.apple\." | sort)
if [ -n "$SAFARI_EXT" ]; then
  echo "$SAFARI_EXT" | while read -r LINE; do log "    [Safari] $LINE"; done
fi
if [ "$EXT_TOTAL" -gt 0 ]; then
  note_mod "$EXT_TOTAL browser extension(s) installed (Chromium-family/Firefox; Safari listed separately)"
else
  [ -z "$SAFARI_EXT" ] && log "    None found."
fi
log "    (Browser extensions run with access to page content — the most common adware/infostealer foothold. Prune anything you don't actively use.)"

log "\n  ${BOLD}Library plug-in directories (both domains — anything listed is third-party):${RESET}"
PLUGDIR_FOUND=false
for BASE in "$HOME/Library" "/Library"; do
  for SUB in "QuickLook" "PreferencePanes" "Spotlight" "Internet Plug-Ins" "Mail/Bundles" "Audio/Plug-Ins/HAL" "Audio/Plug-Ins/Components" "Audio/MIDI Drivers" "Services" "Input Methods" "ColorPickers" \
             "Frameworks" "Filesystems" "Screen Savers" "Components" "Contextual Menu Items" "Automator" "Widgets" "Keyboard Layouts" "CoreMediaIO/Plug-Ins/DAL" "Image Capture/Devices" "Scripting Additions" "DriverExtensions" "Extensions"; do
    # /Library/Extensions is covered with kexts in section 10.
    [ "$BASE/$SUB" = "/Library/Extensions" ] && continue
    D="$BASE/$SUB"
    [ -d "$D" ] || continue
    CONTENTS=$(ls -A "$D" 2>/dev/null)
    [ -z "$CONTENTS" ] && continue
    PLUGDIR_FOUND=true
    log "    $D:"
    echo "$CONTENTS" | while read -r I; do log "      - $I"; done
    note_mod "$(echo "$CONTENTS" | wc -l | tr -d ' ') item(s) in $D"
  done
done
[ "$PLUGDIR_FOUND" = false ] && log "    All empty — no third-party plug-ins."

# ============================================================
# [14] LIBRARY LEFTOVERS (added 2026-09)
# ============================================================
section "LIBRARY LEFTOVERS (data of apps that are no longer installed)"
log "  Dragging an app to the Trash leaves its sandbox container, saved window"
log "  state and prefs behind. Orphans are matched by bundle ID against every"
log "  installed app/extension, then double-checked with Spotlight.\n"

INSTALLED_IDS="$AUDIT_DIR/.installed_ids.$$"
: > "$INSTALLED_IDS"
while IFS= read -r APP; do
  /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP/Contents/Info.plist" 2>/dev/null >> "$INSTALLED_IDS"
  # iOS/iPadOS apps on Apple Silicon keep Info.plist in the wrapped bundle.
  for W in "$APP"/Wrapper/*.app; do
    [ -f "$W/Info.plist" ] && /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$W/Info.plist" 2>/dev/null >> "$INSTALLED_IDS"
  done
  # Nested helpers/extensions own containers too and often don't share the
  # parent's ID prefix (com.foo.app vs com.foo.helper).
  for N in "$APP"/Contents/{PlugIns,Extensions,Helpers,XPCServices,Library/LoginItems,Library/LaunchServices}/*.{app,appex,xpc}; do
    [ -f "$N/Contents/Info.plist" ] && /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$N/Contents/Info.plist" 2>/dev/null >> "$INSTALLED_IDS"
  done
done < <(find /Applications "$HOME/Applications" /System/Applications /Library/Application\ Support -maxdepth 4 -name "*.app" -prune 2>/dev/null)
sort -u -o "$INSTALLED_IDS" "$INSTALLED_IDS"

# 0 = installed (exact id, a parent id — e.g. an app extension of an
# installed app — or found by Spotlight), 1 = orphan.
id_installed() {
  local id="$1" p
  case "$id" in [A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9].*) id="${id#*.}" ;; esac  # strip Team ID prefix
  p="$id"
  while [ -n "$p" ]; do
    grep -qxF "$p" "$INSTALLED_IDS" && return 0
    case "$p" in *.*.*) p="${p%.*}" ;; *) break ;; esac
  done
  [ -n "$(mdfind "kMDItemCFBundleIdentifier == '$id'" 2>/dev/null | head -1)" ] && return 0
  return 1
}

log "  ${BOLD}Orphaned sandbox containers (~/Library/Containers):${RESET}"
ORPH_C=0
while IFS= read -r CID; do
  case "$CID" in com.apple.*|*-*-*-*-*|"") continue ;; esac   # Apple, UUID-named
  id_installed "$CID" && continue
  ORPH_C=$((ORPH_C + 1))
  CSIZE=""
  [ "$HAS_FDA" = true ] && CSIZE=" ($(du -sh "$HOME/Library/Containers/$CID" 2>/dev/null | cut -f1))"
  log "    ${YELLOW}[ORPHAN]${RESET} $CID$CSIZE"
done < <(ls -A "$HOME/Library/Containers" 2>/dev/null)
if [ "$ORPH_C" -gt 0 ]; then
  REVIEW_ONLY+=("$ORPH_C orphaned app container(s) in ~/Library/Containers — may hold data you want; remove via the app's uninstaller or Finder")
  [ "$HAS_FDA" = false ] && log "    (sizes need Full Disk Access)"
else
  log "    None."
fi

log "\n  ${BOLD}Orphaned Application Scripts (~/Library/Application Scripts):${RESET}"
ORPH_S=0
while IFS= read -r SID; do
  case "$SID" in com.apple.*|"") continue ;; esac
  id_installed "$SID" && continue
  ORPH_S=$((ORPH_S + 1))
  log "    ${YELLOW}[ORPHAN]${RESET} $SID"
done < <(ls -A "$HOME/Library/Application Scripts" 2>/dev/null)
[ "$ORPH_S" -eq 0 ] && log "    None."
[ "$ORPH_S" -gt 0 ] && note_mod "$ORPH_S orphaned Application Scripts folder(s)"

# Saved window state is pure cache — safe to quarantine.
log "\n  ${BOLD}Orphaned saved window state (~/Library/Saved Application State):${RESET}"
ORPH_W=0
while IFS= read -r ST; do
  SID="${ST%.savedState}"
  case "$SID" in com.apple.*|"") continue ;; esac
  id_installed "$SID" && continue
  ORPH_W=$((ORPH_W + 1))
  log "    ${YELLOW}[ORPHAN]${RESET} $ST"
  SAFE_CANDIDATES+=("$HOME/Library/Saved Application State/$ST")
done < <(ls -A "$HOME/Library/Saved Application State" 2>/dev/null | grep '\.savedState$')
[ "$ORPH_W" -eq 0 ] && log "    None."

# Preferences are noisy (CLI tools and helpers write them too), so these are
# informational only — never flagged.
log "\n  ${BOLD}Preference files with no matching installed app (informational):${RESET}"
ORPH_P=0
ORPH_P_LIST=""
while IFS= read -r PF; do
  PID="${PF%.plist}"
  case "$PID" in com.apple.*|.GlobalPreferences*|*ByHost*|loginwindow|"") continue ;; esac
  case "$PID" in *.*.*) ;; *) continue ;; esac   # only reverse-DNS names
  id_installed "$PID" && continue
  ORPH_P=$((ORPH_P + 1))
  ORPH_P_LIST="$ORPH_P_LIST $PID"
done < <(ls -A "$HOME/Library/Preferences" 2>/dev/null | grep '\.plist$')
if [ "$ORPH_P" -gt 0 ]; then
  log "    $ORPH_P file(s):"
  for P in $ORPH_P_LIST; do log "      $P"; done
  note_mod "$ORPH_P preference file(s) without an installed app (leftovers or CLI tools)"
else
  log "    None."
fi

log "\n  ${BOLD}Third-party vendor folders in /Library/Application Support:${RESET}"
ls -A "/Library/Application Support" 2>/dev/null | grep -vE '^(Apple|\.DS_Store|\.localized|com\.apple\..*|CrashReporter|Script Editor|iLifeMediaBrowser|ProApps|Printers|Logs|DiskImages|com\.apple\.TCC|Mobile Documents)$' | \
  while IFS= read -r V; do log "    $V ($(du -sh "/Library/Application Support/$V" 2>/dev/null | cut -f1))"; done
rm -f "$INSTALLED_IDS"

# ============================================================
# [15] NETWORK CONFIGURATION MODIFICATIONS
# ============================================================
section "NETWORK CONFIGURATION (proxies, DNS, VPN, remote-access services)"

log "  ${BOLD}System proxies (scutil --proxy):${RESET}"
PROXY_OUT=$(scutil --proxy 2>/dev/null)
PROXY_ON=$(echo "$PROXY_OUT" | grep -E "(HTTP|HTTPS|SOCKS|ProxyAutoConfig)Enable : 1")
if [ -n "$PROXY_ON" ]; then
  echo "$PROXY_ON" | while read -r LINE; do log "    ${RED}[PROXY ENABLED]${RESET} $LINE"; done
  echo "$PROXY_OUT" | grep -E "(HTTP|HTTPS|SOCKS)Proxy : |ProxyAutoConfigURLString" | while read -r LINE; do log "      $LINE"; done
  REVIEW_ONLY+=("System proxy enabled — verify it's yours (proxies can silently reroute all traffic)")
else
  log "    None enabled (factory default)."
fi

log "\n  ${BOLD}DNS servers in use:${RESET}"
scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}' | sort -u | while read -r NS; do
  log "    $NS"
done
log "    (Expect your router/ISP or a resolver you chose — 1.1.1.1, 8.8.8.8, 9.9.9.9. Anything else: verify.)"

log "\n  ${BOLD}VPN services (scutil --nc list):${RESET}"
VPN_LIST=$(scutil --nc list 2>/dev/null | grep -v "^$")
if [ -n "$VPN_LIST" ]; then
  echo "$VPN_LIST" | while read -r LINE; do log "    $LINE"; done
else
  log "    None configured."
fi

log "\n  ${BOLD}Remote-access & sharing services:${RESET}"
DISABLED_DUMP=$(launchctl print-disabled system 2>/dev/null)
for SVC_LABEL in com.openssh.sshd com.apple.screensharing com.apple.smbd com.apple.AEServer; do
  case "$SVC_LABEL" in
    com.openssh.sshd)        SVC_NAME="Remote Login (SSH)" ;;
    com.apple.screensharing) SVC_NAME="Screen Sharing" ;;
    com.apple.smbd)          SVC_NAME="File Sharing (SMB)" ;;
    com.apple.AEServer)      SVC_NAME="Remote Apple Events" ;;
  esac
  SVC_LINE=$(echo "$DISABLED_DUMP" | grep "\"$SVC_LABEL\"")
  if echo "$SVC_LINE" | grep -q "false"; then
    log "    ${YELLOW}[ENABLED]${RESET} $SVC_NAME — fine if deliberate; it's a remote door into this Mac."
    note_mod "$SVC_NAME enabled"
  elif [ -n "$SVC_LINE" ]; then
    log "    ${GREEN}[disabled]${RESET} $SVC_NAME"
  else
    log "    [unknown] $SVC_NAME — not in launchctl disabled list (check System Settings → Sharing)"
  fi
done

# Remote Management (ARD) is a superset of Screen Sharing: full remote
# control plus remote command execution.
if [ -f "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd" ] || \
   ps axo comm= 2>/dev/null | grep -q '/ARDAgent$'; then
  log "    ${YELLOW}[ENABLED]${RESET} Remote Management (ARD) — remote control + remote command execution"
  note_mod "Remote Management (ARD) enabled"
else
  log "    ${GREEN}[disabled]${RESET} Remote Management (ARD)"
fi
if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -q 'Enabled = 1'; then
  log "    ${YELLOW}[ENABLED]${RESET} Internet Sharing — this Mac is routing traffic for other devices"
  note_mod "Internet Sharing enabled"
fi
if cupsctl 2>/dev/null | grep -q '_share_printers=1'; then
  log "    ${YELLOW}[ENABLED]${RESET} Printer Sharing"
  note_mod "Printer Sharing enabled"
fi

log "\n  ${BOLD}Application Firewall rules:${RESET}"
BLOCKALL=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null)
log "    Block all incoming: $(echo "${BLOCKALL:-unknown}" | sed 's/^ *//' | head -1)"
SIGNED_OK=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>/dev/null | tr '\n' ' ')
[ -n "$SIGNED_OK" ] && log "    Auto-allow signed software: $SIGNED_OK"
FW_APPS=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | awk '
  /^[0-9]+ :/ { sub(/^[0-9]+ :[ \t]*/, ""); sub(/[ \t]+$/, ""); app=$0; next }
  /incoming connections/ { gsub(/[()\t]/, ""); sub(/^ +/, ""); if (app != "") print app " — " $0; app="" }')
if [ -n "$FW_APPS" ]; then
  echo "$FW_APPS" | while IFS= read -r LINE; do log "    $LINE"; done
  FW_ALLOW_N=$(echo "$FW_APPS" | grep -c "Allow" || true)
  [ "${FW_ALLOW_N:-0}" -gt 0 ] && note_mod "$FW_ALLOW_N app(s) explicitly allowed through the firewall"
else
  log "    No per-app rules."
fi

# ============================================================
# [16] ACTIVE OUTBOUND CONNECTIONS
# ============================================================
section "ACTIVE OUTBOUND CONNECTIONS"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1, $9}' | sort -u | \
grep -v "^Google\|^Slack\|^Zoom\|rapportd\|identitys" | while read -r LINE; do
  log "  ${YELLOW}[CONN]${RESET} $LINE"
done

# ============================================================
# [17] DISK USAGE
# ============================================================
section "DISK USAGE — LARGEST ITEMS"

log "\n  Top 15 largest items under \$HOME (excluding ~/Library to keep this fast):"
# -print0/xargs -0: safe for any filename (spaces, quotes, newlines).
find "$HOME" -mindepth 1 -maxdepth 2 -not -path "$HOME/Library*" -exec du -sh {} + 2>/dev/null | sort -rh | head -15 | while read -r LINE; do log "    $LINE"; done

log "\n  ${BOLD}Volume:${RESET}"
df -h /System/Volumes/Data 2>/dev/null | tail -1 | awk '{print "    Data volume: "$3" used of "$2" ("$5"), "$4" free"}' | while IFS= read -r LINE; do log "$LINE"; done
SNAPS=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c 'com.apple' || true)
[ "${SNAPS:-0}" -gt 0 ] && log "    Time Machine local snapshots: $SNAPS (purgeable; macOS frees them under pressure)"
SWAP=$(sysctl -n vm.swapusage 2>/dev/null)
[ -n "$SWAP" ] && log "    Swap: $SWAP"

# ~/Library is usually the biggest hidden consumer. Without Full Disk Access
# du can't enter protected folders (Mail, Messages, Containers…) and may
# trigger TCC prompts, so only the unprotected ones are sized then.
log "\n  ${BOLD}~/Library — largest subfolders:${RESET}"
if [ "$HAS_FDA" = true ]; then
  find "$HOME/Library" -mindepth 1 -maxdepth 1 -exec du -sh {} + 2>/dev/null | sort -rh | head -12 | \
    while IFS= read -r LINE; do log "    $LINE"; done
  log "\n  ${BOLD}~/Library/Application Support + Containers + Group Containers — largest:${RESET}"
  find "$HOME/Library/Application Support" "$HOME/Library/Containers" "$HOME/Library/Group Containers" -mindepth 1 -maxdepth 1 -exec du -sh {} + 2>/dev/null | sort -rh | head -15 | while IFS= read -r LINE; do log "    $LINE"; done
else
  for LD in Caches Logs Developer "Application Support" Android; do
    [ -d "$HOME/Library/$LD" ] || continue
    log "    $(du -sh "$HOME/Library/$LD" 2>/dev/null | cut -f1)	~/Library/$LD"
  done
  log "    (Grant Terminal Full Disk Access for the full ~/Library + Containers breakdown.)"
fi

log "\n  ${BOLD}/Library — largest subfolders:${RESET}"
find /Library -mindepth 1 -maxdepth 1 -exec du -sh {} + 2>/dev/null | sort -rh | head -8 | \
  while IFS= read -r LINE; do log "    $LINE"; done

# Regenerable developer / package-manager caches: rebuilt on demand, so
# they're quarantine-eligible. Anything that holds unique data is excluded.
log "\n  ${BOLD}Regenerable developer caches:${RESET}"
DEVCACHE_FOUND=false
for DC in "$HOME/Library/Developer/Xcode/DerivedData" \
          "$HOME/Library/Developer/Xcode/iOS DeviceSupport" \
          "$HOME/Library/Developer/Xcode/watchOS DeviceSupport" \
          "$HOME/Library/Developer/CoreSimulator/Caches" \
          "$HOME/.npm/_cacache" "$HOME/.cache/pip" "$HOME/.gradle/caches" \
          "$HOME/Library/Caches/Yarn" "$HOME/.cache/huggingface/xet"; do
  [ -d "$DC" ] || continue
  DSZ=$(du -sh "$DC" 2>/dev/null | cut -f1)
  DEVCACHE_FOUND=true
  log "    $DSZ	$DC"
  case "$DC" in "$HOME/Library/Caches/"*) ;; *) SAFE_CANDIDATES+=("$DC") ;; esac  # ~/Library/Caches is already a candidate
done
[ "$DEVCACHE_FOUND" = false ] && log "    None."
# Big but NOT disposable — reported so you know where the space went.
for BIG in "$HOME/Library/Developer/CoreSimulator/Devices" "$HOME/Library/Application Support/MobileSync/Backup" \
           "$HOME/.ollama/models" "$HOME/.cache/huggingface/hub" "$HOME/.lmstudio/models" "$HOME/Library/Containers/com.docker.docker"; do
  [ -d "$BIG" ] || continue
  BSZ=$(du -sh "$BIG" 2>/dev/null | cut -f1)
  [ -n "$BSZ" ] && log "    $BSZ	$BIG  (not auto-flagged: holds data — prune from the owning app)"
done

log "\n  ${BOLD}Files larger than 1 GB under \$HOME:${RESET}"
if [ "$HAS_FDA" = true ]; then
  BIGF=$(find "$HOME" -xdev -type f -size +1G -exec du -h {} + 2>/dev/null | sort -rh | head -20)
else
  BIGF=$(find "$HOME" -xdev \( -path "$HOME/Library/Containers" -o -path "$HOME/Library/Group Containers" -o -path "$HOME/Library/Mail" -o -path "$HOME/Library/Messages" \) -prune -o -type f -size +1G -exec du -h {} + 2>/dev/null | sort -rh | head -20)
fi
if [ -n "$BIGF" ]; then
  echo "$BIGF" | while IFS= read -r LINE; do log "    $LINE"; done
else
  log "    None."
fi

log ""
for CACHE in "$HOME/Library/Caches" "$HOME/Library/Logs" "$HOME/.Trash"; do
  if [ -d "$CACHE" ]; then
    SIZE=$(du -sh "$CACHE" 2>/dev/null | cut -f1)
    log "  $CACHE — ${SIZE:-unreadable (needs Full Disk Access)}"
    [ "$CACHE" != "$HOME/.Trash" ] && SAFE_CANDIDATES+=("$CACHE")
  fi
done

# ============================================================
# [18] SUMMARY & QUARANTINE OFFER
# ============================================================
section "SUMMARY" nofence

logt "\n  ${BOLD}For manual review (security-relevant, never auto-removed):${RESET}"
md ""
md "### Manual review — security-relevant (${#REVIEW_ONLY[@]})"
md ""
if [ ${#REVIEW_ONLY[@]} -eq 0 ]; then
  logt "    None."
  md "None."
else
  for ITEM in "${REVIEW_ONLY[@]}"; do
    logt "    ${YELLOW}[-]${RESET} $ITEM"
    md "- $ITEM"
  done
fi

logt "\n  ${BOLD}Non-factory modifications (informational — vouch for each):${RESET}"
md ""
md "### Non-factory modifications — informational (${#NONFACTORY[@]})"
md ""
if [ ${#NONFACTORY[@]} -eq 0 ]; then
  logt "    None recorded."
  md "None recorded."
else
  for ITEM in "${NONFACTORY[@]}"; do
    logt "    [·] $ITEM"
    md "- $ITEM"
  done
fi

logt "\n  ${BOLD}Quarantine candidates (known junk/cache, safe to move):${RESET}"
md ""
md "### Quarantine candidates (${#SAFE_CANDIDATES[@]})"
md ""
if [ ${#SAFE_CANDIDATES[@]} -eq 0 ]; then
  logt "    None flagged this run."
  md "None flagged this run."
else
  for ITEM in "${SAFE_CANDIDATES[@]}"; do
    SIZE=$(du -sh "$ITEM" 2>/dev/null | cut -f1)
    logt "    ${RED}[-]${RESET} $ITEM ($SIZE)"
    md "- $ITEM ($SIZE)"
  done

  if [ "$QUARANTINE_MODE" = true ]; then
    divider
    echo ""
    echo -e "${BOLD}${RED}Type QUARANTINE to move the items above into $QUARANTINE_DIR/$TS/${RESET}"
    echo "(Nothing is deleted. Run 'bash mac_audit.sh --purge-quarantine' later to actually remove it.)"
    echo "Type anything else to abort:"
    read -r CONFIRM
    if [ "$CONFIRM" = "QUARANTINE" ]; then
      DEST="$QUARANTINE_DIR/$TS"
      mkdir -p "$DEST"
      IDX=0
      for ITEM in "${SAFE_CANDIDATES[@]}"; do
        # Prefix with an index so two candidates with the same basename
        # (e.g. ~/Library/Caches and ~/foo/Caches) can't collide/overwrite.
        IDX=$((IDX + 1))
        TARGET="$DEST/${IDX}__$(basename "$ITEM")"
        mv "$ITEM" "$TARGET" 2>/dev/null \
          && { log "  ${GREEN}[QUARANTINED]${RESET} $ITEM"; echo "$TARGET -> $ITEM" >> "$DEST/RESTORE_MAP.txt"; } \
          || log "  ${RED}[FAILED]${RESET} $ITEM"
      done
      [ -f "$DEST/RESTORE_MAP.txt" ] && log "  Restore map written to $DEST/RESTORE_MAP.txt (original paths, for manual restore)."
      log "\n${GREEN}Done. Items moved, not deleted. Review $DEST whenever you like.${RESET}"
    else
      log "\n${YELLOW}Aborted. Nothing was touched.${RESET}"
    fi
  else
    logt "\n  Re-run with ${BOLD}--quarantine${RESET} to move these into a reversible quarantine folder."
  fi
fi

# Copy the machine-readable inventory next to the markdown report so the
# weekly Claude maintenance task can read it from the repo's outputs/.
cp "$INVENTORY" "$OUT_DIR/inventory.json" 2>/dev/null

md_close_fence
md ""
md "---"
md "_Generated by mac_audit.sh. Read-only by default; nothing was changed unless a QUARANTINE confirmation was typed. Text report: \`$REPORT\`_"

divider
logt "\n${BOLD}Audit complete.${RESET}"
logt "Report   : $REPORT"
logt "Markdown : $MD_REPORT"
logt "Inventory: $INVENTORY (copied to $OUT_DIR/inventory.json for the weekly Claude task)"
logt "Quarantine: $QUARANTINE_DIR (run --purge-quarantine to permanently empty it)"
logt ""
