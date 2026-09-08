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
#   [1] security posture        [2] software inventory (+ pkg receipts)
#   [3] unused apps             [4] local AI tools (CVE checks)
#   [5] suspicious artifacts    [6] data collectors
#   [7] TCC permissions         [8] LaunchAgents/Daemons (+ malware IOCs)
#   [9] other persistence (login items, cron, at, hooks, legacy startup)
#   [10] system modifications (/etc, kexts, system extensions, profiles,
#        users, root CAs, shell rc files, /usr/local & /opt)
#   [11] app extensions & plug-ins (pluginkit, browser extensions,
#        QuickLook/Spotlight/PreferencePanes/etc.)
#   [12] network configuration (proxies, DNS, VPN, remote access services)
#   [13] outbound connections   [14] disk usage   [15] summary
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
}

json_escape() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
note_mod() { NONFACTORY+=("$1"); }

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
  echo "| Text report | \`$REPORT\` |"
} > "$MD_REPORT"

clear
logt "${BOLD}mac_audit.sh — $(date)${RESET}"
logt "Host  : $HOSTNAME_HR — macOS ${MACOS_VER:-unknown} (${MACOS_BUILD:-?})"
logt "Report: $REPORT"
logt "MD    : $MD_REPORT"
logt "Mode  : $([ "$QUARANTINE_MODE" = true ] && echo "QUARANTINE (will offer to move junk, never deletes)" || echo "READ-ONLY (nothing will be touched)")"

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
  OUTDATED=$(brew outdated 2>/dev/null)
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
  mas outdated 2>/dev/null | while read -r LINE; do log "    ${YELLOW}[OUTDATED]${RESET} $LINE"; done
else
  log "    'mas' CLI not installed — skip (install with: brew install mas)"
fi

log "\n  ${BOLD}Global pip / npm packages (extra attack surface):${RESET}"
command -v pip3 >/dev/null 2>&1 && pip3 list --user 2>/dev/null | tail -n +3 | while read -r LINE; do log "    [pip --user] $LINE"; done
command -v npm  >/dev/null 2>&1 && npm list -g --depth=0 2>/dev/null | tail -n +2 | \
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
lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{print $1, $9}' | sort -u | \
grep -v "127\.0\.0\.1\|\[::1\]\|localhost" | while read -r LINE; do
  log "    ${RED}[EXPOSED?]${RESET} $LINE"
done
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

TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -r "$TCC_DB" ]; then
  for SERVICE in kTCCServiceSystemPolicyAllFiles kTCCServiceMicrophone kTCCServiceCamera kTCCServiceAccessibility kTCCServiceScreenCapture; do
    log "\n  $SERVICE:"
    sqlite3 "$TCC_DB" "SELECT client, auth_value FROM access WHERE service='$SERVICE';" 2>/dev/null | \
    while IFS='|' read -r CLIENT AUTH; do
      STATUS=$( [ "$AUTH" = "2" ] && echo "${RED}ALLOWED${RESET}" || echo "${GREEN}DENIED${RESET}" )
      log "    $STATUS — $CLIENT"
    done
  done
else
  log "  ${YELLOW}TCC database not readable.${RESET} Enable Full Disk Access for Terminal to read it: System Settings → Privacy & Security → Full Disk Access."
fi

# ============================================================
# [8] LAUNCH AGENTS & DAEMONS
# ============================================================
section "LAUNCH AGENTS & DAEMONS (auto-start persistence)"

for LAUNCH_DIR in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [ -d "$LAUNCH_DIR" ]; then
    log "\n  ${BOLD}$LAUNCH_DIR:${RESET}"
    find "$LAUNCH_DIR" -maxdepth 1 -name "*.plist" 2>/dev/null | grep -v "com\.apple\." | while read -r PLIST; do
      PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$PLIST" 2>/dev/null)
      [ -z "$PROGRAM" ] && PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :Program" "$PLIST" 2>/dev/null)
      # Fallback (added 2026-07-03): both keystone plists showed "unknown
      # binary" — PlistBuddy can fail on some plist layouts. plutil -p prints
      # any plist (binary or XML); grab the first ProgramArguments entry.
      [ -z "$PROGRAM" ] && PROGRAM=$(plutil -p "$PLIST" 2>/dev/null | \
        awk -F'"' '/"ProgramArguments"/{f=1; next} f && NF >= 2 {print $2; exit}')
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
    done
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
LOGIN_ITEMS=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
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
LHOOK=$(defaults read com.apple.loginwindow LoginHook 2>/dev/null)
LOHOOK=$(defaults read com.apple.loginwindow LogoutHook 2>/dev/null)
if [ -n "$LHOOK" ] || [ -n "$LOHOOK" ]; then
  [ -n "$LHOOK" ]  && log "    ${RED}[FOUND]${RESET} LoginHook  → $LHOOK"
  [ -n "$LOHOOK" ] && log "    ${RED}[FOUND]${RESET} LogoutHook → $LOHOOK"
  REVIEW_ONLY+=("Login/Logout hook set (legacy persistence mechanism): ${LHOOK:-}${LHOOK:+ }${LOHOOK:-}")
else
  log "    None set (expected)."
fi

log "\n  ${BOLD}Cron / at jobs (rare on modern macOS — anything here is a deliberate add or persistence):${RESET}"
USER_CRON=$(crontab -l 2>/dev/null | grep -vE '^\s*#|^\s*$')
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
log "    (LaunchAgents/Daemons are covered in section 8.)"

# ============================================================
# [10] SYSTEM MODIFICATIONS (/etc, kexts, profiles, users, CAs)
# ============================================================
section "SYSTEM MODIFICATIONS (/etc, kernel/system extensions, profiles, users, trust)"

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
  log "    None at user level. (System-level check needs sudo: 'sudo profiles list')."
fi

log "\n  ${BOLD}Local user accounts (UID >= 500) & admin group:${RESET}"
dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500' | while read -r U UID_; do
  log "    [USER] $U (uid $UID_)"
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

log "\n  ${BOLD}Custom certificate trust settings (MITM proxies, corp CAs):${RESET}"
TRUST_USER=$(security dump-trust-settings 2>/dev/null | grep -c "Cert " || true)
TRUST_ADMIN=$(security dump-trust-settings -d 2>/dev/null | grep -c "Cert " || true)
if [ "${TRUST_USER:-0}" -gt 0 ] || [ "${TRUST_ADMIN:-0}" -gt 0 ]; then
  log "    ${YELLOW}[MODIFIED]${RESET} Custom trust settings: ${TRUST_USER:-0} user-domain, ${TRUST_ADMIN:-0} admin-domain cert(s)."
  security dump-trust-settings 2>/dev/null | grep "Cert " | while read -r LINE; do log "      [user]  $LINE"; done
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
  SUS=$(grep -nE '(curl|wget)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|/bin/)?sh|eval[[:space:]].*base64|base64[[:space:]]+(-d|-D|--decode)[^|]*\|[[:space:]]*(ba|z)?sh|DYLD_INSERT_LIBRARIES' "$RCF" 2>/dev/null)
  if [ -n "$SUS" ]; then
    echo "$SUS" | while read -r LINE; do log "      ${RED}[SUSPICIOUS]${RESET} $LINE"; done
    REVIEW_ONLY+=("Suspicious line(s) in ~/$RC — pipe-to-shell / base64-eval / dylib injection pattern")
  fi
done

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
# [11] APP EXTENSIONS & PLUG-INS
# ============================================================
section "APP EXTENSIONS & PLUG-INS (pluginkit, browsers, Library plug-in dirs)"

log "  ${BOLD}Third-party app extensions (pluginkit — Finder sync, share sheets, widgets):${RESET}"
PK_OUT=$(pluginkit -m 2>/dev/null | grep -v "com\.apple\." | sort)
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
SAFARI_EXT=$(pluginkit -m -p com.apple.Safari.web-extension -p com.apple.Safari.extension 2>/dev/null | grep -v "com\.apple\." | sort)
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
  for SUB in "QuickLook" "PreferencePanes" "Spotlight" "Internet Plug-Ins" "Mail/Bundles" "Audio/Plug-Ins/HAL" "Audio/Plug-Ins/Components" "Services" "Input Methods" "ColorPickers"; do
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
# [12] NETWORK CONFIGURATION MODIFICATIONS
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
for SVC_LABEL in com.openssh.sshd com.apple.screensharing com.apple.smbd; do
  case "$SVC_LABEL" in
    com.openssh.sshd)        SVC_NAME="Remote Login (SSH)" ;;
    com.apple.screensharing) SVC_NAME="Screen Sharing" ;;
    com.apple.smbd)          SVC_NAME="File Sharing (SMB)" ;;
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

# ============================================================
# [13] ACTIVE OUTBOUND CONNECTIONS
# ============================================================
section "ACTIVE OUTBOUND CONNECTIONS"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1, $9}' | sort -u | \
grep -v "^Google\|^Slack\|^Zoom\|rapportd\|identitys" | while read -r LINE; do
  log "  ${YELLOW}[CONN]${RESET} $LINE"
done

# ============================================================
# [14] DISK USAGE
# ============================================================
section "DISK USAGE — LARGEST ITEMS"

log "\n  Top 15 largest items under \$HOME (excluding ~/Library to keep this fast):"
# -print0/xargs -0: safe for any filename (spaces, quotes, newlines).
find "$HOME" -mindepth 1 -maxdepth 2 -not -path "$HOME/Library*" -print0 2>/dev/null | \
xargs -0 du -sh 2>/dev/null | sort -rh | head -15 | while read -r LINE; do log "    $LINE"; done

for CACHE in "$HOME/Library/Caches" "$HOME/Library/Logs" "$HOME/.Trash"; do
  if [ -d "$CACHE" ]; then
    SIZE=$(du -sh "$CACHE" 2>/dev/null | cut -f1)
    log "  $CACHE — ${SIZE:-unreadable (needs Full Disk Access)}"
    [ "$CACHE" != "$HOME/.Trash" ] && SAFE_CANDIDATES+=("$CACHE")
  fi
done

# ============================================================
# [15] SUMMARY & QUARANTINE OFFER
# ============================================================
section "SUMMARY"
md_close_fence

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
