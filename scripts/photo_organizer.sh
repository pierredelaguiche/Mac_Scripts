#!/bin/bash
# ============================================================
# photo_organizer.sh — GoPro-aware photo/video organizer for macOS
#
# Organizes a messy media folder into a date + event hybrid layout:
#
#   Photos/
#     2023/
#       2023-03-14_Adelboden march 2023/   <- existing named folders preserved
#       2023-07-02_event/                  <- auto-clustered (rename freely)
#       2023-07-02_event-2/
#
# USAGE
#   bash photo_organizer.sh [DIR]                 # DRY RUN (default): report only
#   bash photo_organizer.sh [DIR] --apply         # actually move/delete/repair
#   bash photo_organizer.sh --undo <undo.log>     # reverse a previous --apply
#
# OPTIONS
#   --apply           Execute the plan (default is a read-only dry run).
#   --repair-exif     Rewrite missing/implausible EXIF dates with the inferred
#                     date (requires exiftool; originals backed up first).
#   --gap-hours N     Hours of inactivity that start a new event (default 6).
#   --min-year N      Oldest plausible capture year (default 2004).
#   --undo FILE       Reverse the moves/deletions/EXIF edits in an undo log.
#
# SAFETY MODEL
#   - Dry run by default: nothing is touched without --apply.
#   - Files are only ever MOVED, never modified — except:
#       * perfect duplicates (identical checksum) are deleted; the undo log
#         records which identical copy was kept, so deletion is reversible
#         by re-copying the kept file.
#       * --repair-exif rewrites date tags; the original file is backed up
#         to ~/.photo_organizer/exif_backups/ first.
#   - Every --apply writes an undo log. --undo replays it in reverse.
#
# METADATA HANDLING
#   Capture date is taken from, in order of preference:
#     1. EXIF/QuickTime (DateTimeOriginal, CreateDate, MediaCreateDate)
#        via exiftool, if installed (brew install exiftool)
#     2. File modification time, when EXIF is missing or implausible
#        (GoPro clocks reset to a factory date after battery pulls, so
#        dates before --min-year or in the future are treated as bogus)
#
# GOPRO AWARENESS
#   - Chaptered videos (GOPR0666 + GP010666 / GH01xxxx + GH02xxxx / GX...)
#     inherit the first chapter's date so all chapters land together.
#   - LRV/THM sidecars follow their parent video.
#   - Burst/timelapse photos (G0020342.JPG) cluster naturally by time.
# ============================================================

set -u

# ---------- defaults ----------
PHOTOS_DIR=""
APPLY=false
REPAIR_EXIF=false
UNDO_FILE=""
GAP_HOURS=6
MIN_YEAR=2004

STATE_DIR="$HOME/.photo_organizer"
TS="$(date +%Y-%m-%d_%H%M%S)"

# ---------- arg parsing ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)        APPLY=true ;;
    --repair-exif)  REPAIR_EXIF=true ;;
    --gap-hours)    shift; GAP_HOURS="${1:?--gap-hours needs a value}" ;;
    --min-year)     shift; MIN_YEAR="${1:?--min-year needs a value}" ;;
    --undo)         shift; UNDO_FILE="${1:?--undo needs a log file}" ;;
    -h|--help)      sed -n '2,50p' "$0"; exit 0 ;;
    -*)             echo "Unknown option: $1" >&2; exit 2 ;;
    *)              PHOTOS_DIR="$1" ;;
  esac
  shift
done
PHOTOS_DIR="${PHOTOS_DIR:-$HOME/Desktop/Photos}"
GAP_SECONDS=$((GAP_HOURS * 3600))

# ---------- portable helpers ----------
# Branch on OS explicitly: on GNU/Linux `stat -f` is *filesystem* stat — it
# "succeeds" with multi-line output, so a BSD-first-with-fallback chain
# silently returns garbage instead of failing over.
IS_MAC=false; [ "$(uname)" = "Darwin" ] && IS_MAC=true
file_mtime()  { if $IS_MAC; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi; }
file_size()   { if $IS_MAC; then stat -f %z "$1" 2>/dev/null; else stat -c %s "$1" 2>/dev/null; fi; }
epoch_fmt()   { if $IS_MAC; then date -r "$1" +"$2" 2>/dev/null; else date -d "@$1" +"$2" 2>/dev/null; fi; }
hash_file()   { if $IS_MAC; then md5 -q "$1" 2>/dev/null; else md5sum "$1" 2>/dev/null | awk '{print $1}'; fi; }
reverse_file(){ if $IS_MAC; then tail -r "$1" 2>/dev/null; else tac "$1" 2>/dev/null; fi; }
lower()       { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
upper()       { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

log() { echo "$@"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ============================================================
# MODE: --undo — replay an undo log in reverse
# ============================================================
if [ -n "$UNDO_FILE" ]; then
  [ -f "$UNDO_FILE" ] || die "Undo log not found: $UNDO_FILE"
  log "Undoing actions from: $UNDO_FILE"
  UNDONE=0; FAILED=0
  while IFS=$'\t' read -r ACTION A B; do
    [ -z "$ACTION" ] && continue
    case "$ACTION" in
      MV)   # A=original location, B=where it was moved to
        if [ -e "$B" ]; then
          mkdir -p "$(dirname "$A")"
          if mv "$B" "$A" 2>/dev/null; then UNDONE=$((UNDONE+1)); else
            echo "  [FAILED] mv '$B' -> '$A'"; FAILED=$((FAILED+1)); fi
        else
          echo "  [MISSING] $B (already moved?)"; FAILED=$((FAILED+1))
        fi ;;
      DUPDEL)  # A=deleted path, B=identical kept copy
        if [ -e "$A" ]; then
          echo "  [SKIP] $A already exists"
        elif [ -e "$B" ]; then
          mkdir -p "$(dirname "$A")"
          if cp -p "$B" "$A" 2>/dev/null; then UNDONE=$((UNDONE+1)); else
            echo "  [FAILED] restore '$A' from '$B'"; FAILED=$((FAILED+1)); fi
        else
          echo "  [MISSING] kept copy $B — cannot restore $A"; FAILED=$((FAILED+1))
        fi ;;
      EXIF)  # A=repaired file, B=pre-repair backup
        if [ -e "$B" ]; then
          if cp -p "$B" "$A" 2>/dev/null; then UNDONE=$((UNDONE+1)); else
            echo "  [FAILED] restore EXIF backup for '$A'"; FAILED=$((FAILED+1)); fi
        else
          echo "  [MISSING] EXIF backup $B"; FAILED=$((FAILED+1))
        fi ;;
    esac
  done < <(reverse_file "$UNDO_FILE")
  log "Undo complete: $UNDONE reversed, $FAILED failed/skipped."
  exit 0
fi

# ============================================================
# SETUP
# ============================================================
[ -d "$PHOTOS_DIR" ] || die "Directory not found: $PHOTOS_DIR"
# Normalize to an absolute path without a trailing slash.
PHOTOS_DIR="$(cd "$PHOTOS_DIR" && pwd)"

mkdir -p "$STATE_DIR/reports" "$STATE_DIR/logs" "$STATE_DIR/exif_backups"
PLAN="$STATE_DIR/reports/plan_$TS.txt"
UNDO_LOG="$STATE_DIR/logs/undo_$TS.log"

TMP="$(mktemp -d)" || die "mktemp failed"
trap 'rm -rf "$TMP"' EXIT

HAVE_EXIFTOOL=false
command -v exiftool >/dev/null 2>&1 && HAVE_EXIFTOOL=true
if [ "$REPAIR_EXIF" = true ] && [ "$HAVE_EXIFTOOL" = false ]; then
  die "--repair-exif requires exiftool (brew install exiftool)"
fi

NOW_EPOCH=$(date +%s)
MAX_EPOCH=$((NOW_EPOCH + 86400))

log "photo_organizer.sh — $(date)"
log "Target : $PHOTOS_DIR"
log "Mode   : $([ "$APPLY" = true ] && echo "APPLY (files will be moved)" || echo "DRY RUN (report only, nothing touched)")"
log "exiftool: $([ "$HAVE_EXIFTOOL" = true ] && echo "found (EXIF dates used)" || echo "NOT FOUND — falling back to file dates. 'brew install exiftool' for accurate dates.")"
log ""

# ============================================================
# [1] BULK EXIF EXTRACTION (single exiftool pass — fast)
# ============================================================
EXIF_TSV="$TMP/exif.tsv"
: > "$EXIF_TSV"
if [ "$HAVE_EXIFTOOL" = true ]; then
  log "[1/6] Reading EXIF metadata (one pass over the whole tree)..."
  exiftool -r -q -q -f -T -d %s \
    -FilePath -DateTimeOriginal -CreateDate -MediaCreateDate \
    "$PHOTOS_DIR" > "$EXIF_TSV" 2>/dev/null || true
else
  log "[1/6] Skipping EXIF pass (no exiftool)."
fi

# exif_epoch <abs path> -> echoes epoch or ""
exif_epoch() {
  awk -F'\t' -v p="$1" '$1 == p {
    for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print $i; exit }
  }' "$EXIF_TSV"
}

# ============================================================
# [2] INVENTORY
# ============================================================
log "[2/6] Scanning files..."

# Directories whose names carry no meaning (camera dumps) — files inside are
# "loose". Anything else ("Adelboden march 2023") is a named event to preserve.
is_generic_dir() {
  case "$(lower "$1")" in
    gopro|dcim|1[0-9][0-9]gopro|camera|"camera uploads"|camera*roll|photos|pictures| \
    misc|unsorted|untitled|"new folder"|import*|export*|iphone*|screenshots|sdcard|backup*)
      return 0 ;;
  esac
  return 1
}

# RECORDS columns (tab-separated):
# 1 abs_path  2 epoch  3 date_source(EXIF|INFERRED|MTIME)  4 fam:vid  5 chap  6 group(N:reldir|L)  7 ext
RECORDS="$TMP/records.tsv"
: > "$RECORDS"
SKIPPED_ORGANIZED=0
SKIPPED_TAB=0

while IFS= read -r -d '' F; do
  REL="${F#"$PHOTOS_DIR"/}"

  case "$REL" in *"$(printf '\t')"*)
    echo "  [WARN] path contains a tab, skipping: $REL" ; SKIPPED_TAB=$((SKIPPED_TAB+1)); continue ;;
  esac

  # Already organized — leave alone so re-runs are safe. Both layouts count:
  # nested (YYYY/YYYY-MM-DD_event/) and flattened (YYYY-MM-DD_event/ at root,
  # after Pierre's 2026-07 manual flatten).
  if printf '%s' "$REL" | grep -Eq '^([0-9]{4}/)?[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
    SKIPPED_ORGANIZED=$((SKIPPED_ORGANIZED+1)); continue
  fi

  BASE="$(basename "$F")"
  EXT="$(lower "${BASE##*.}")"
  STEM="$(upper "${BASE%.*}")"

  # --- GoPro filename parsing ---
  # "-" (not "") for absent values: tab is IFS whitespace, so consecutive
  # tabs collapse during `read` and empty fields would shift every column.
  FAMVID="-"; CHAP="-"
  case "$STEM" in
    GOPR[0-9][0-9][0-9][0-9])                      FAMVID="O:${STEM#GOPR}"; CHAP="01" ;;
    GP[0-9][0-9][0-9][0-9][0-9][0-9])              FAMVID="O:${STEM:4:4}";  CHAP="${STEM:2:2}" ;;
    GH[0-9][0-9][0-9][0-9][0-9][0-9])              FAMVID="H:${STEM:4:4}";  CHAP="${STEM:2:2}" ;;
    GX[0-9][0-9][0-9][0-9][0-9][0-9])              FAMVID="X:${STEM:4:4}";  CHAP="${STEM:2:2}" ;;
    GL[0-9][0-9][0-9][0-9][0-9][0-9])              FAMVID="L:${STEM:4:4}";  CHAP="${STEM:2:2}" ;;
  esac

  # --- capture date ---
  SRC="MTIME"
  EPOCH=""
  if [ "$HAVE_EXIFTOOL" = true ]; then
    EPOCH="$(exif_epoch "$F")"
    [ -n "$EPOCH" ] && SRC="EXIF"
  fi
  MT="$(file_mtime "$F")"
  if [ -n "$EPOCH" ]; then
    YEAR="$(epoch_fmt "$EPOCH" %Y)"
    if [ -z "$YEAR" ] || [ "$YEAR" -lt "$MIN_YEAR" ] || [ "$EPOCH" -gt "$MAX_EPOCH" ]; then
      # GoPro factory-reset date or corrupt tag — fall back to file mtime.
      EPOCH="$MT"; SRC="INFERRED"
    fi
  else
    EPOCH="$MT"
  fi
  [ -z "$EPOCH" ] && { echo "  [WARN] no usable date, skipping: $REL"; continue; }

  # --- named-event vs loose ---
  GROUP="L"
  DIRREL="$(dirname "$REL")"
  if [ "$DIRREL" != "." ]; then
    ACCUM=""
    OLDIFS="$IFS"; IFS='/'
    for COMP in $DIRREL; do
      ACCUM="${ACCUM:+$ACCUM/}$COMP"
      if ! is_generic_dir "$COMP"; then
        GROUP="N:$ACCUM"   # deepest named dir wins (loop continues)
      fi
    done
    IFS="$OLDIFS"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$F" "$EPOCH" "$SRC" "$FAMVID" "$CHAP" "$GROUP" "$EXT" >> "$RECORDS"
done < <(find "$PHOTOS_DIR" -type f -not -name '.*' \( \
  -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.heic' -o -iname '*.heif' \
  -o -iname '*.mp4' -o -iname '*.mov' -o -iname '*.avi' -o -iname '*.mts' -o -iname '*.360' \
  -o -iname '*.dng' -o -iname '*.gpr' -o -iname '*.raw' -o -iname '*.arw' -o -iname '*.cr2' -o -iname '*.nef' \
  -o -iname '*.lrv' -o -iname '*.thm' \) -print0 2>/dev/null)

TOTAL=$(wc -l < "$RECORDS" | tr -d ' ')
[ "$TOTAL" -gt 0 ] || { log "No media files to organize. ($SKIPPED_ORGANIZED already organized.)"; exit 0; }
log "  $TOTAL files to consider ($SKIPPED_ORGANIZED already organized, skipped)."

# ============================================================
# [3] CHAPTER / SIDECAR DATE INHERITANCE
# ============================================================
log "[3/6] Grouping GoPro chapters and sidecars..."

# Base map: first chapter (01) of each video, primary media types only.
BASEMAP="$TMP/basemap.tsv"   # famvid \t epoch
awk -F'\t' '$5 == "01" && $4 != "-" && $7 ~ /^(mp4|mov|avi|360|jpg)$/ { if (!($4 in seen)) { seen[$4]=1; print $4 "\t" $2 } }' \
  "$RECORDS" > "$BASEMAP"

base_epoch() {  # $1 famvid -> epoch or ""
  awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$BASEMAP"
}

RECORDS2="$TMP/records2.tsv"
: > "$RECORDS2"
INHERITED=0
while IFS=$'\t' read -r F EPOCH SRC FAMVID CHAP GROUP EXT; do
  NEW=""
  if [ "$FAMVID" != "-" ]; then
    FAM="${FAMVID%%:*}"; VID="${FAMVID#*:}"
    if [ "$EXT" = "lrv" ] || [ "$EXT" = "thm" ]; then
      # Sidecars: inherit from their parent video (GL sidecars pair with GX/GH).
      if [ "$FAM" = "L" ]; then
        NEW="$(base_epoch "X:$VID")"; [ -z "$NEW" ] && NEW="$(base_epoch "H:$VID")"
      else
        NEW="$(base_epoch "$FAMVID")"
      fi
    elif [ "$CHAP" != "-" ] && [ "$CHAP" != "01" ]; then
      # Later chapters of a long recording: use chapter 1's date.
      NEW="$(base_epoch "$FAMVID")"
    fi
  fi
  if [ -n "$NEW" ] && [ "$NEW" != "$EPOCH" ]; then
    EPOCH="$NEW"; SRC="${SRC}+CHAPTER"; INHERITED=$((INHERITED+1))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$F" "$EPOCH" "$SRC" "$FAMVID" "$CHAP" "$GROUP" "$EXT" >> "$RECORDS2"
done < "$RECORDS"
log "  $INHERITED chapter/sidecar files inherited their parent's date."

# ============================================================
# [4] PERFECT-DUPLICATE DETECTION (size, then checksum)
# ============================================================
log "[4/6] Detecting perfect duplicates..."

SIZES="$TMP/sizes.tsv"
while IFS=$'\t' read -r F REST; do
  printf '%s\t%s\n' "$(file_size "$F")" "$F"
done < "$RECORDS2" > "$SIZES"

# Only hash files whose size appears more than once.
DUPES="$TMP/dupes.tsv"   # deleted \t kept
: > "$DUPES"
HASHES="$TMP/hashes.tsv"
: > "$HASHES"
awk -F'\t' 'NR==FNR { c[$1]++; next } c[$1] > 1 { print $2 }' "$SIZES" "$SIZES" | \
while IFS= read -r F; do
  printf '%s\t%s\n' "$(hash_file "$F")" "$F"
done > "$HASHES"

# One file per hash is kept — prefer the shortest basename ("GOPR0554.JPG"
# beats "GOPR0554 copy.JPG"), then lexicographic; the rest are duplicates.
awk -F'\t' '{
  n = split($2, parts, "/"); base = parts[n]
  if (!($1 in kb) || length(base) < length(kb[$1]) || (length(base) == length(kb[$1]) && $2 < kp[$1])) {
    kb[$1] = base; kp[$1] = $2
  }
  hash_of[NR] = $1; path_of[NR] = $2
}
END {
  for (i = 1; i <= NR; i++) if (path_of[i] != kp[hash_of[i]]) print path_of[i] "\t" kp[hash_of[i]]
}' "$HASHES" > "$DUPES"

DUP_COUNT=$(wc -l < "$DUPES" | tr -d ' ')
DUP_BYTES=0
if [ "$DUP_COUNT" -gt 0 ]; then
  while IFS=$'\t' read -r DEL KEEP; do
    SZ="$(file_size "$DEL")"; DUP_BYTES=$((DUP_BYTES + ${SZ:-0}))
  done < "$DUPES"
fi
log "  $DUP_COUNT perfect duplicates found ($(awk -v b="$DUP_BYTES" 'BEGIN{printf "%.1f MB", b/1048576}'))."

is_dupe() { awk -F'\t' -v p="$1" '$1 == p { found=1; exit } END { exit !found }' "$DUPES"; }

# ============================================================
# [5] PLAN: events + targets
# ============================================================
log "[5/6] Building the plan..."

# Filter out dupes, then split named-group files from loose files.
# NOTE: not the NR==FNR two-file idiom — when the first file is empty (zero
# duplicates), NR==FNR stays true for the second file and every record gets
# skipped. FILENAME comparison is immune to that.
CLEAN="$TMP/clean.tsv"
awk -F'\t' -v dup="$DUPES" 'FILENAME == dup { d[$1]=1; next } !($1 in d)' "$DUPES" "$RECORDS2" > "$CLEAN"

PLANNED="$TMP/planned_moves.tsv"   # src \t dst
DSTLIST="$TMP/dst_taken.txt"
: > "$PLANNED"; : > "$DSTLIST"

# unique_dst <candidate abs dst> -> echoes collision-free dst
unique_dst() {
  local D="$1" N=1 STEM EXT CAND
  if ! grep -Fxq "$D" "$DSTLIST" 2>/dev/null && [ ! -e "$D" ]; then
    printf '%s\n' "$D"; return
  fi
  STEM="${D%.*}"; EXT="${D##*.}"
  while :; do
    CAND="${STEM}_$N.$EXT"
    if ! grep -Fxq "$CAND" "$DSTLIST" 2>/dev/null && [ ! -e "$CAND" ]; then
      printf '%s\n' "$CAND"; return
    fi
    N=$((N+1))
  done
}

plan_move() {  # $1 src abs, $2 target dir rel
  local SRC="$1" DSTDIR="$PHOTOS_DIR/$2" DST
  DST="$DSTDIR/$(basename "$SRC")"
  if [ "$SRC" = "$DST" ]; then return; fi
  DST="$(unique_dst "$DST")"
  printf '%s\n' "$DST" >> "$DSTLIST"
  printf '%s\t%s\n' "$SRC" "$DST" >> "$PLANNED"
}

# --- 5a. named event folders: keep together, date by earliest file ---
NAMED_DIRS="$TMP/named_dirs.txt"
awk -F'\t' '$6 ~ /^N:/ { print substr($6, 3) }' "$CLEAN" | sort -u > "$NAMED_DIRS"
NAMED_COUNT=$(wc -l < "$NAMED_DIRS" | tr -d ' ')

while IFS= read -r NDIR; do
  [ -z "$NDIR" ] && continue
  EARLIEST=$(awk -F'\t' -v g="N:$NDIR" '$6 == g { if (min == "" || $2 < min) min = $2 } END { print min }' "$CLEAN")
  DAY="$(epoch_fmt "$EARLIEST" %Y-%m-%d)"
  YEAR="$(epoch_fmt "$EARLIEST" %Y)"
  TARGET="$YEAR/${DAY}_$(basename "$NDIR")"
  while IFS=$'\t' read -r F EPOCH SRC FAMVID CHAP GROUP EXT; do
    plan_move "$F" "$TARGET"
  done < <(awk -F'\t' -v g="N:$NDIR" '$6 == g' "$CLEAN")
done < "$NAMED_DIRS"

# --- 5b. loose files: cluster by time gap ---
LOOSE_SORTED="$TMP/loose_sorted.tsv"
awk -F'\t' '$6 == "L"' "$CLEAN" | sort -t "$(printf '\t')" -k2,2n -k4,4 -k5,5 > "$LOOSE_SORTED"

EVENT_COUNT=0
PREV_EPOCH=""
EVENT_TARGET=""
EVENT_NAMES="$TMP/event_names.txt"; : > "$EVENT_NAMES"

while IFS=$'\t' read -r F EPOCH SRC FAMVID CHAP GROUP EXT; do
  if [ -z "$PREV_EPOCH" ] || [ $((EPOCH - PREV_EPOCH)) -gt "$GAP_SECONDS" ]; then
    EVENT_COUNT=$((EVENT_COUNT+1))
    DAY="$(epoch_fmt "$EPOCH" %Y-%m-%d)"
    YEAR="$(epoch_fmt "$EPOCH" %Y)"
    CAND="$YEAR/${DAY}_event"
    N=2
    while grep -Fxq "$CAND" "$EVENT_NAMES" 2>/dev/null || [ -d "$PHOTOS_DIR/$CAND" ]; do
      CAND="$YEAR/${DAY}_event-$N"; N=$((N+1))
    done
    EVENT_TARGET="$CAND"
    printf '%s\n' "$EVENT_TARGET" >> "$EVENT_NAMES"
  fi
  plan_move "$F" "$EVENT_TARGET"
  PREV_EPOCH="$EPOCH"
done < "$LOOSE_SORTED"

MOVE_COUNT=$(wc -l < "$PLANNED" | tr -d ' ')

# --- 5c. EXIF repair candidates ---
REPAIR_LIST="$TMP/repair.tsv"   # src \t epoch
awk -F'\t' '$3 ~ /^(INFERRED|MTIME)/ && $7 !~ /^(lrv|thm)$/ { print $1 "\t" $2 }' "$CLEAN" > "$REPAIR_LIST"
REPAIR_COUNT=$(wc -l < "$REPAIR_LIST" | tr -d ' ')

# ============================================================
# WRITE PLAN REPORT
# ============================================================
{
  echo "photo_organizer plan — $(date)"
  echo "Target: $PHOTOS_DIR"
  echo ""
  echo "== MOVES ($MOVE_COUNT) =="
  while IFS=$'\t' read -r S D; do
    echo "  ${S#"$PHOTOS_DIR"/}  ->  ${D#"$PHOTOS_DIR"/}"
  done < "$PLANNED"
  echo ""
  echo "== PERFECT DUPLICATES TO DELETE ($DUP_COUNT) =="
  while IFS=$'\t' read -r DEL KEEP; do
    echo "  DELETE ${DEL#"$PHOTOS_DIR"/}   (identical copy kept: ${KEEP#"$PHOTOS_DIR"/})"
  done < "$DUPES"
  echo ""
  echo "== FILES WITH MISSING/IMPLAUSIBLE EXIF DATES ($REPAIR_COUNT) =="
  while IFS=$'\t' read -r S E; do
    echo "  ${S#"$PHOTOS_DIR"/}  (inferred: $(epoch_fmt "$E" '%Y-%m-%d %H:%M:%S'))"
  done < "$REPAIR_LIST"
} > "$PLAN"

log ""
log "PLAN SUMMARY"
log "  Files scanned            : $TOTAL"
log "  Moves planned            : $MOVE_COUNT"
log "  Named event folders kept : $NAMED_COUNT"
log "  Auto-detected events     : $EVENT_COUNT (gap > ${GAP_HOURS}h starts a new one)"
log "  Perfect duplicates       : $DUP_COUNT ($(awk -v b="$DUP_BYTES" 'BEGIN{printf "%.1f MB", b/1048576}') reclaimable)"
log "  Bad/missing EXIF dates   : $REPAIR_COUNT $([ "$REPAIR_EXIF" = true ] && echo "(will be repaired)" || echo "(detect only; use --repair-exif to fix)")"
log "  Full plan                : $PLAN"

# ============================================================
# [6] EXECUTE (only with --apply)
# ============================================================
if [ "$APPLY" != true ]; then
  log ""
  log "DRY RUN — nothing was touched. Review the plan, then re-run with --apply."
  exit 0
fi

log ""
log "[6/6] Applying..."
: > "$UNDO_LOG"
MOVED=0; DELETED=0; REPAIRED=0; ERRORS=0

# Duplicates first (so we never move a file we're about to delete).
while IFS=$'\t' read -r DEL KEEP; do
  if rm "$DEL" 2>/dev/null; then
    printf 'DUPDEL\t%s\t%s\n' "$DEL" "$KEEP" >> "$UNDO_LOG"
    DELETED=$((DELETED+1))
  else
    echo "  [FAILED] delete $DEL"; ERRORS=$((ERRORS+1))
  fi
done < "$DUPES"

# Moves.
while IFS=$'\t' read -r S D; do
  mkdir -p "$(dirname "$D")"
  if [ -e "$D" ]; then
    echo "  [SKIP] target exists unexpectedly: $D"; ERRORS=$((ERRORS+1)); continue
  fi
  if mv "$S" "$D" 2>/dev/null; then
    printf 'MV\t%s\t%s\n' "$S" "$D" >> "$UNDO_LOG"
    MOVED=$((MOVED+1))
  else
    echo "  [FAILED] mv $S"; ERRORS=$((ERRORS+1))
  fi
done < "$PLANNED"

# EXIF repair (after moves, on final paths).
if [ "$REPAIR_EXIF" = true ] && [ "$REPAIR_COUNT" -gt 0 ]; then
  BKDIR="$STATE_DIR/exif_backups/$TS"
  mkdir -p "$BKDIR"
  I=0
  while IFS=$'\t' read -r S E; do
    # The file may have moved — find its final location.
    FINAL="$(awk -F'\t' -v p="$S" '$1 == p { print $2; exit }' "$PLANNED")"
    [ -z "$FINAL" ] && FINAL="$S"
    [ -e "$FINAL" ] || continue
    STAMP="$(epoch_fmt "$E" '%Y:%m:%d %H:%M:%S')"
    if exiftool -q -m -overwrite_original_in_place=false \
        "-AllDates=$STAMP" "-MediaCreateDate=$STAMP" "-TrackCreateDate=$STAMP" \
        "$FINAL" >/dev/null 2>&1; then
      I=$((I+1))
      BK="$BKDIR/${I}__$(basename "$FINAL")"
      if [ -e "${FINAL}_original" ] && mv "${FINAL}_original" "$BK" 2>/dev/null; then
        printf 'EXIF\t%s\t%s\n' "$FINAL" "$BK" >> "$UNDO_LOG"
      fi
      REPAIRED=$((REPAIRED+1))
    else
      echo "  [FAILED] EXIF repair: $FINAL"; ERRORS=$((ERRORS+1))
    fi
  done < "$REPAIR_LIST"
fi

# Clean up now-empty source directories (cosmetic; not logged).
find "$PHOTOS_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null

log ""
log "DONE"
log "  Moved    : $MOVED"
log "  Deleted  : $DELETED perfect duplicates"
log "  Repaired : $REPAIRED EXIF dates (backups in $STATE_DIR/exif_backups/$TS)"
log "  Errors   : $ERRORS"
log "  Undo log : $UNDO_LOG"
log ""
log "To reverse everything:  bash photo_organizer.sh --undo \"$UNDO_LOG\""
