# homelab scripts

Pierre's macOS maintenance repository: security auditing, package updating, and file organization. All scripts are written for the stock macOS `/bin/bash` 3.2 (no associative arrays, no GNU-only flags) unless noted, and all follow the same philosophy: **read-only or dry-run by default, destructive actions gated behind explicit flags and typed confirmations, everything reversible.**

## Layout

```
.
├── README.md            this file
├── CHANGELOG.md         maintenance history for all scripts
├── scripts/             the tools
│   ├── mac_audit.sh
│   ├── package_updater.sh
│   ├── photo_organizer.sh
│   └── bookmark_organizer.py
└── outputs/             generated reports (gitignored, safe to empty)
    ├── mac_audit_<ts>.md
    └── inventory.json   machine-readable software inventory (latest run)
```

## scripts/mac_audit.sh

Security, non-factory-modification, and disk audit. 15 sections: security posture, software inventory (apps, brew, pip/npm, pkg receipts), unused apps, local AI tools (with CVE version checks), suspicious artifacts, data collectors, TCC permissions, LaunchAgents/Daemons (with malware IOC checks), other persistence (login items, cron, hooks), system modifications (/etc, kexts, system extensions, profiles, users, certificate trust, shell rc files), app extensions and browser extensions, network configuration, outbound connections, disk usage, summary.

```
bash scripts/mac_audit.sh                     # read-only audit
bash scripts/mac_audit.sh --quarantine        # offer to MOVE flagged junk (typed confirmation)
bash scripts/mac_audit.sh --purge-quarantine  # the only deleting mode (second confirmation)
```

Output: colored terminal + text report in `~/.mac_audit/reports/`, Markdown report in `outputs/`. Some checks report more with Full Disk Access granted to Terminal (TCC database) or sudo (`sudo sfltool dumpbtm`, system-level profiles); the script never requires either.

Safety model: default run touches nothing. `--quarantine` only moves, never deletes, and writes a restore map. Root-owned or unclear items are never quarantine-eligible. Non-factory modifications are reported, never reverted — many are deliberate (Touch ID sudo, /etc/hosts dev entries); the report exists so you can vouch for each one.

A weekly scheduled Claude task researches new CVEs and macOS malware IOCs for the software in `outputs/inventory.json` and updates this script's detection lists, logging every change to CHANGELOG.md.

## scripts/package_updater.sh

Runs brew/pip/npm updates only when the connection is judged secure: VPN actually carrying traffic, an SSID listed in `~/.mac_audit/trusted_ssids.txt`, or a wired connection. No sudo. Exit 1 without touching anything if the connection is untrusted. Logs to `~/.mac_audit/logs/`.

## scripts/photo_organizer.sh

GoPro-aware photo/video organizer for `~/Desktop/Photos` (or a given dir). Date + event hybrid layout, chaptered-video and sidecar grouping, checksum-verified duplicate removal, optional EXIF date repair. Dry run by default; every `--apply` writes an undo log that `--undo` replays in reverse. Wants `exiftool` (`brew install exiftool`) for accurate dates.

## scripts/bookmark_organizer.py

Checks, dedupes, and re-clusters a Netscape-format bookmarks export (Python 3, stdlib only). Read-only on the input; writes a new importable HTML plus a Markdown report. Link-check results cached in `~/.bookmark_organizer/` for 30 days.

## Conventions

Script state and logs live under `~/.mac_audit/`, `~/.photo_organizer/`, `~/.bookmark_organizer/` — not in this repo. `outputs/` holds generated reports only and can be emptied at any time. Every substantive change to a script gets a dated CHANGELOG.md entry with reasoning and sources; safety models are never weakened silently.
