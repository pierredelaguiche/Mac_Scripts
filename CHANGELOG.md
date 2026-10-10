# CHANGELOG

## 2026-09-23 — mac_audit.sh: root / Library / user coverage

Goal: go beyond the invoking user's view and cover the root filesystem, both Library domains, and every account. Safety model unchanged. The default run is still read-only, nothing new is ever auto-removed, and every new finding goes to the review or informational lists. The one new quarantine-eligible class is regenerable caches (orphaned saved window state, Xcode DerivedData/DeviceSupport, simulator caches, npm/pip/gradle caches).

### Bugs fixed
- **Section 8 IOC hits never reached the summary.** The LaunchAgent loop ran as `find | grep | while` (a subshell), so the SHub "Reaper" and AdLoad hits were appended to a throwaway copy of `REVIEW_ONLY`. This is the same class of bug that was fixed in section 3 in 2026-07. The loop now uses process substitution.
- **TCC read the wrong database.** Full Disk Access, Accessibility, Screen Recording and Input Monitoring grants live in the *system* TCC.db, and the old code only read the user one. Both are read now. The readability test was also `[ -r ]`, which is always true under TCC. It now does a real read.
- **Login/Logout hooks were invisible.** They're written into root's `com.apple.loginwindow` domain, and the check read the user's domain. It now reads the plist files directly.
- **Markdown fences broke** when a section's first `log` ran inside a piped subshell. The fence is now opened in `section()`.
- **Exposed listening ports** were logged but never added to the summary.
- `com.apple.*`-named plists in third-party launchd dirs were skipped outright, which hid Apple-name masquerading. They're now checked by signature.

### New checks
- **Posture:** authenticated root (sealed system volume), XProtect version and age, Software Update auto-install keys, auto-login and `/etc/kcpassword`, guest account, screen lock, Lockdown Mode, `DYLD_INSERT_LIBRARIES` in launchd.
- **Launchd:** program signature, missing programs, interpreter-wrapped payloads, inline curl/base64/eval, DYLD injection, programs running from hidden/temp/shared paths, and **privilege escalation** (a root LaunchDaemon whose plist, program or program folder is writable by non-root). Under sudo, other users' and root's LaunchAgents are included.
- **Persistence:** non-factory periodic scripts and `*.local` hooks, authorization plugins, DirectoryServices/PAM plug-ins. Under sudo: `sfltool dumpbtm` (non-Apple items) and all crontabs.
- **System:** `/etc/zshenv` etc. scanned for injected commands, PATH hijack (`.` or world-writable dirs before /usr/bin), MDM enrollment. Under sudo: sudoers NOPASSWD rules.
- **New section, root & privilege surface:** non-factory entries at `/`, SUID/SGID binaries outside SIP paths, `/Library/PrivilegedHelperTools` (signature, orphaned helpers, writability), world-writable paths in /Library, /usr/local and /opt. Under sudo: `/var/root`.
- **New section, user accounts & home:** UID-0 clones, UID<500 accounts with login shells, remote logins from wtmp, home permissions, SSH (authorized_keys fingerprints, unencrypted or loose-permission private keys, ssh config command execution), plaintext credential files and their modes, items in home not owned by you. Under sudo: other users' SSH keys and rc files.
- **Suspicious artifacts:** hidden dot-entries in both Library domains, /Users/Shared contents, executables staged in /tmp, /var/tmp and $TMPDIR.
- **New section, Library leftovers:** orphaned ~/Library/Containers, Application Scripts, Saved Application State and Preferences. Matching is by bundle ID against installed apps and their nested helpers/extensions, with Spotlight as a fallback.
- **Extensions:** more plug-in dirs (Frameworks, Filesystems, Screen Savers, CoreMediaIO DAL, Scripting Additions, DriverExtensions, …).
- **Network:** Remote Apple Events, Remote Management (ARD), Internet Sharing, Printer Sharing, firewall block-all / allow-signed / per-app rules.
- **Disk:** Data volume usage, local snapshots, swap, ~/Library and /Library breakdowns (full breakdown only with FDA, to avoid TCC prompts), regenerable developer caches, big data folders (simulators, iOS backups, model stores), files >1 GB.

### Privilege handling
- `sudo bash scripts/mac_audit.sh` is supported. It resolves the invoking user's home, runs user-context commands via `sudo -u`, chowns every report back on exit, and refuses `--quarantine`.
- The header shows the privilege level and Full Disk Access state.

### Compatibility
- Still stock `/bin/bash` 3.2: no associative arrays, no `case` inside `$(…)` (3.2 mis-parses it), `set -u`-safe array use, and BSD `stat`/`find`. `find | xargs du` was replaced with `find -exec du {} +` because BSD xargs runs `du` on `.` when its input is empty.
