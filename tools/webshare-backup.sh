#!/bin/bash
# WebShare backup: daily hard-link snapshots of user files + metadata archive.
# Docs: docs/backup.md
#
#   webshare-backup.sh              run a backup (cron: /etc/cron.d/webshare-backup)
#   webshare-backup.sh --list       list snapshots
#
# Settings can be overridden in /etc/default/webshare-backup:
#   WS_ROOT=/var/www/webshare  BACKUP_DIR=/var/backups/webshare
#   KEEP_DATA=14  KEEP_META=30  EXTRA_DEST=   (optional second copy, e.g. NFS)
set -euo pipefail

WS_ROOT=/var/www/webshare
BACKUP_DIR=/var/backups/webshare
KEEP_DATA=14
KEEP_META=30
EXTRA_DEST=
[ -r /etc/default/webshare-backup ] && . /etc/default/webshare-backup

LOG=/var/log/webshare-backup.log
STAMP=$(date +%Y-%m-%d_%H%M)
DATA_DIR="$BACKUP_DIR/data"
META_DIR="$BACKUP_DIR/meta"
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

if [ "${1:-}" = "--list" ]; then
    ls -1 "$DATA_DIR" "$META_DIR" 2>/dev/null; exit 0
fi

umask 077
mkdir -p "$DATA_DIR" "$META_DIR"
chmod 700 "$BACKUP_DIR"

exec 9>"$BACKUP_DIR/.lock"
flock -n 9 || { log "another backup is running, skipped"; exit 0; }

# Refuse to fill the disk: need at least 5 GB free on the backup filesystem
free_kb=$(df -Pk "$BACKUP_DIR" | awk 'NR==2 {print $4}')
if [ "$free_kb" -lt $((5 * 1024 * 1024)) ]; then
    log "ERROR: less than 5 GB free on $BACKUP_DIR, backup aborted"; exit 1
fi

# A run that died midway leaves a .partial directory; it is never used as a base
rm -rf "$DATA_DIR"/*.partial

# 1. User files and texts: hard-link snapshot, unchanged files take no space
prev=$(ls -1d "$DATA_DIR"/20* 2>/dev/null | tail -1 || true)
link=()
[ -n "$prev" ] && link=(--link-dest="$prev/files")
mkdir -p "$DATA_DIR/$STAMP.partial"
rsync -a --delete "${link[@]}" "$WS_ROOT/files/" "$DATA_DIR/$STAMP.partial/files/"
rsync -a --delete ${prev:+--link-dest="$prev/texts"} "$WS_ROOT/texts/" "$DATA_DIR/$STAMP.partial/texts/"
mv "$DATA_DIR/$STAMP.partial" "$DATA_DIR/$STAMP"

# 2. Metadata: users, shares, keys, config, audit log (regular dotfiles only, symlinks skipped)
( cd "$WS_ROOT" && find . src -maxdepth 1 -type f -name '.*' ! -name '.git*' -print0 \
    | tar --null -czf "$META_DIR/meta-$STAMP.tar.gz" -T - )

# 3. Retention
ls -1d "$DATA_DIR"/20* | head -n -"$KEEP_DATA" | xargs -r rm -rf
ls -1 "$META_DIR"/meta-*.tar.gz | head -n -"$KEEP_META" | xargs -r rm -f

# 4. Optional second copy (latest snapshot + metadata)
if [ -n "$EXTRA_DEST" ]; then
    mkdir -p "$EXTRA_DEST"
    rsync -a --delete "$DATA_DIR/$STAMP/" "$EXTRA_DEST/data/"
    rsync -a "$META_DIR/meta-$STAMP.tar.gz" "$EXTRA_DEST/meta/"
fi

size=$(du -sh "$DATA_DIR/$STAMP" | cut -f1)
log "OK snapshot $STAMP ($size apparent), $(ls -1d "$DATA_DIR"/20* | wc -l) snapshots kept"
printf '{"time":%s,"snapshot":"%s","status":"ok"}\n' "$(date +%s)" "$STAMP" > "$BACKUP_DIR/last.json"
