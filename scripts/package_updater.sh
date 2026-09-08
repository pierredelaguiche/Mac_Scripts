#!/bin/bash
#
# package_updater.sh
#
# Standalone updater: only runs brew/pip/npm updates when the current
# network connection is judged "secure" (VPN active, a trusted Wi-Fi
# SSID, or a wired/non-Wi-Fi connection). No sudo. No dependency on
# mac_audit.sh — safe to run on its own.
#
# Exit codes:
#   0 = ran (even if individual package updates failed)
#   1 = connection considered insecure, nothing was run
#
# Options:
#   --skip-network-check   Bypass the VPN/trusted-SSID/wired check entirely
#                           (e.g. on a network you know is safe but that the
#                           heuristics above can't detect, like enterprise
#                           Wi-Fi with no VPN).

set -u

LOG_PREFIX="[package_updater]"

# Persist every run to a log file (added 2026-07-03: runs were unreviewable
# after the fact — output went only to the terminal). Same state dir as
# mac_audit so everything lives in one place.
LOG_DIR="$HOME/.mac_audit/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/package_updater_$(date +%Y-%m-%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "${LOG_PREFIX} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# ---------------------------------------------------------------------------
# Connection security check
# ---------------------------------------------------------------------------
is_connection_secure() {
    # 1. VPN active.
    #
    # FIX 2026-07: the old check passed if ANY utun interface was UP. Modern
    # macOS always has several utun interfaces up (iCloud Private Relay,
    # Network Extensions, AWDL plumbing) even with no VPN configured — so the
    # "secure connection" gate was effectively always open and this script
    # would happily update packages on any coffee-shop Wi-Fi. The check now
    # requires actual evidence of a VPN carrying traffic: either the default
    # route goes through a tunnel interface, or scutil reports a Connected
    # VPN service.
    if command -v route >/dev/null 2>&1; then
        local vpn_iface
        vpn_iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
        case "$vpn_iface" in
            utun*|ppp*|ipsec*|wg*)
                log "VPN check: default route is via tunnel interface '$vpn_iface'."
                return 0
                ;;
        esac
    fi

    if command -v scutil >/dev/null 2>&1; then
        # Match only the connection-status line, not e.g. a VPN profile
        # literally named "Connected something".
        if scutil --nc list 2>/dev/null | grep -q '^\* (Connected)'; then
            log "VPN check: scutil --nc list reports a Connected service."
            return 0
        fi
    fi

    # 2. Trusted Wi-Fi SSID: compare current SSID against ~/.mac_audit/trusted_ssids.txt
    #    Fail silently (no error output) if that file doesn't exist.
    local trusted_file="$HOME/.mac_audit/trusted_ssids.txt"
    if [ -f "$trusted_file" ]; then
        local current_ssid=""
        if command -v networksetup >/dev/null 2>&1; then
            # Typical en0 is the Wi-Fi interface on most Macs, but allow override
            # by trying to detect the Wi-Fi device name via networksetup first.
            local wifi_dev
            wifi_dev=$(networksetup -listallhardwareports 2>/dev/null \
                | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -n1)
            wifi_dev=${wifi_dev:-en0}
            current_ssid=$(networksetup -getairportnetwork "$wifi_dev" 2>/dev/null \
                | sed -n 's/^Current Wi-Fi Network: //p')

            # Fallback for macOS 14+ where -getairportnetwork is deprecated and
            # may return nothing / "not associated" even when connected:
            # ipconfig getsummary exposes the SSID directly.
            if [ -z "$current_ssid" ] && command -v ipconfig >/dev/null 2>&1; then
                current_ssid=$(ipconfig getsummary "$wifi_dev" 2>/dev/null \
                    | awk -F ' SSID : ' '/ SSID : /{print $2; exit}')
            fi
        fi

        if [ -n "$current_ssid" ]; then
            while IFS= read -r trusted_ssid || [ -n "$trusted_ssid" ]; do
                # Skip blank lines and comments.
                [ -z "$trusted_ssid" ] && continue
                case "$trusted_ssid" in
                    \#*) continue ;;
                esac
                if [ "$current_ssid" = "$trusted_ssid" ]; then
                    log "Wi-Fi check: current SSID '$current_ssid' matches trusted list."
                    return 0
                fi
            done < "$trusted_file"
        fi
    fi
    # else: trusted_ssids.txt absent -> silently skip this check, no error.

    # 3. Wired/no-Wi-Fi: the active default-route interface is not the Wi-Fi device.
    if command -v route >/dev/null 2>&1 && command -v networksetup >/dev/null 2>&1; then
        local default_iface
        default_iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')

        local wifi_dev
        wifi_dev=$(networksetup -listallhardwareports 2>/dev/null \
            | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -n1)
        wifi_dev=${wifi_dev:-en0}

        if [ -n "$default_iface" ] && [ "$default_iface" != "$wifi_dev" ]; then
            log "Wired check: default route is via '$default_iface', not Wi-Fi device '$wifi_dev'."
            return 0
        fi
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Update steps (each continues past individual failures)
# ---------------------------------------------------------------------------
run_brew_update() {
    if ! command -v brew >/dev/null 2>&1; then
        log "Homebrew not found, skipping."
        return
    fi

    log "Running brew update..."
    brew update || log "brew update failed, continuing."

    log "Running brew upgrade..."
    brew upgrade || log "brew upgrade failed, continuing."

    if brew list --cask >/dev/null 2>&1 && [ -n "$(brew list --cask 2>/dev/null)" ]; then
        log "Casks present, running brew upgrade --cask..."
        brew upgrade --cask || log "brew upgrade --cask failed, continuing."
    else
        log "No casks installed, skipping brew upgrade --cask."
    fi
}

run_pip_update() {
    local pip_cmd=""
    if command -v pip3 >/dev/null 2>&1; then
        pip_cmd="pip3"
    elif command -v pip >/dev/null 2>&1; then
        pip_cmd="pip"
    else
        log "pip not found, skipping."
        return
    fi

    log "Checking outdated user-level pip packages..."
    local outdated
    outdated=$("$pip_cmd" list --user --outdated --format=freeze 2>/dev/null | cut -d'=' -f1)

    if [ -z "$outdated" ]; then
        log "No outdated user-level pip packages."
        return
    fi

    local pkg
    for pkg in $outdated; do
        log "Upgrading pip package (user): $pkg"
        if ! "$pip_cmd" install --user --upgrade "$pkg"; then
            log "Failed to upgrade $pkg, continuing. (If the error mentions an 'externally-managed environment', this Python is Homebrew/PEP 668 managed — manage that package with brew or pipx instead.)"
        fi
    done
}

run_npm_update() {
    if ! command -v npm >/dev/null 2>&1; then
        log "npm not found, skipping."
        return
    fi

    log "Checking outdated global npm packages..."
    npm outdated -g || true

    log "Running npm update -g..."
    npm update -g || log "npm update -g failed, continuing."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local skip_network_check=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --skip-network-check)
                skip_network_check=1
                ;;
            *)
                echo "${LOG_PREFIX} Unknown option: $1" >&2
                exit 1
                ;;
        esac
        shift
    done

    log "Starting package_updater.sh"

    if [ "$skip_network_check" -eq 1 ]; then
        log "Network security check bypassed via --skip-network-check. Proceeding with updates (no sudo)."
    else
        if ! is_connection_secure; then
            echo "${LOG_PREFIX} Connection not considered secure (no VPN, no trusted Wi-Fi SSID match, and on Wi-Fi rather than wired). Aborting update — no sudo, no package commands run."
            exit 1
        fi
        log "Connection considered secure. Proceeding with updates (no sudo)."
    fi

    run_brew_update
    run_pip_update
    run_npm_update

    log "package_updater.sh complete. Log: $LOG_FILE"
    exit 0
}

main "$@"
