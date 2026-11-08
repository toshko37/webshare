#!/bin/bash
# WebShare server hardening (idempotent; safe to run again after every update).
# Docs: docs/security-hardening.md, docs/backup.md
#
#   sudo installer/harden.sh [/var/www/webshare]   (default: the parent of this script's dir)
#
# 1. Permissions: data files 600 (config 640), install dir 750, owner www-data
# 2. logs/auth.log for failed logins/passwords + fail2ban filter and jail (if fail2ban is installed)
# 3. logrotate for logs/auth.log
# 4. Daily backup (tools/webshare-backup.sh) when the disk has room for it
# Never overwrites a jail or backup config that already exists.
set -u
WS_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
SRC="$WS_ROOT/src"
WEB_USER=www-data
G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
warn() { echo -e "  ${Y}!${N} $*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -f "$SRC/index.php" ] || { echo "No WebShare install in $WS_ROOT"; exit 1; }
echo "WebShare hardening: $WS_ROOT"

# 1. Permissions --------------------------------------------------------------
for f in "$WS_ROOT"/.*.json "$WS_ROOT"/.htpasswd "$SRC"/.users.json "$SRC"/.login-attempts.json \
         "$SRC"/.auth-attempts.json "$SRC"/.audit.*.json "$SRC"/.upload-guard-state.json "$SRC"/.upload-guard.key; do
    [ -f "$f" ] && [ ! -L "$f" ] && chown "$WEB_USER:$WEB_USER" "$f" && chmod 600 "$f"
done
[ -f "$WS_ROOT/.config.json" ] && chmod 640 "$WS_ROOT/.config.json"
for d in "$SRC/.sessions" "$SRC/.upload-passes"; do [ -d "$d" ] && chmod 700 "$d"; done
chown "$WEB_USER:$WEB_USER" "$WS_ROOT" && chmod 750 "$WS_ROOT"
ok "data files 600, $WS_ROOT 750 (other local users cannot read it)"

# 2. Auth log + fail2ban ------------------------------------------------------
mkdir -p "$WS_ROOT/logs"
touch "$WS_ROOT/logs/auth.log"
chown -R "$WEB_USER:$WEB_USER" "$WS_ROOT/logs"
chmod 750 "$WS_ROOT/logs"; chmod 640 "$WS_ROOT/logs/auth.log"
ok "failed logins/passwords are logged to $WS_ROOT/logs/auth.log"

if [ -d /etc/fail2ban ]; then
    cat > /etc/fail2ban/filter.d/webshare.conf <<'F2B'
# Fail2Ban filter for WebShare (lines written by src/auth-guard.php)
# 2026-11-08 22:50:01 WebShare auth failure: where=login ip=203.0.113.5
[Definition]
failregex = WebShare auth failure: where=\S+ ip=<HOST>$
ignoreregex =
F2B
    if grep -qs '^\[webshare\]' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.conf 2>/dev/null; then
        warn "a [webshare] jail already exists, not changed (logpath should be $WS_ROOT/logs/auth.log)"
    else
        cat > /etc/fail2ban/jail.d/webshare.conf <<JAIL
[webshare]
enabled  = true
port     = http,https
filter   = webshare
logpath  = $WS_ROOT/logs/auth.log
backend  = auto
maxretry = 10
findtime = 600
bantime  = 86400
JAIL
        ok "fail2ban jail 'webshare' created (10 failures in 10 min = 24 h ban)"
    fi
    if fail2ban-client -t >/dev/null 2>&1; then
        systemctl reload fail2ban >/dev/null 2>&1 || fail2ban-client reload >/dev/null 2>&1 || true
    else
        warn "fail2ban configuration test failed, check 'fail2ban-client -t'"
    fi
else
    warn "fail2ban is not installed (apt install fail2ban, then run this script again)"
fi

# 3. logrotate ------------------------------------------------------------------
if [ -d /etc/logrotate.d ]; then
    cat > /etc/logrotate.d/webshare-auth <<LR
$WS_ROOT/logs/auth.log {
    weekly
    rotate 8
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LR
    ok "logrotate for logs/auth.log"
fi

# 4. Backup ---------------------------------------------------------------------
BK_SCRIPT="$WS_ROOT/tools/webshare-backup.sh"
[ -f "$BK_SCRIPT" ] || BK_SCRIPT="$(dirname "$0")/../tools/webshare-backup.sh"
if [ -f /etc/cron.d/webshare-backup ]; then
    ok "backup cron already configured, not changed"
elif [ ! -f "$BK_SCRIPT" ]; then
    warn "tools/webshare-backup.sh not found, backup not configured"
elif ! command -v rsync >/dev/null; then
    warn "rsync is not installed, backup not configured (apt install rsync, then run again)"
else
    data_kb=$(du -sk "$WS_ROOT/files" 2>/dev/null | cut -f1); data_kb=${data_kb:-0}
    mkdir -p /var/backups
    free_kb=$(df -Pk /var/backups | awk 'NR==2 {print $4}')
    if [ "$free_kb" -lt $((data_kb * 2 + 5 * 1024 * 1024)) ]; then
        warn "not enough free disk for local snapshots ($((data_kb / 1024)) MB data, $((free_kb / 1024)) MB free); backup not configured"
    else
        install -m 755 -o root -g root "$BK_SCRIPT" /usr/local/sbin/webshare-backup.sh
        [ -f /etc/default/webshare-backup ] || echo "WS_ROOT=$WS_ROOT" > /etc/default/webshare-backup
        cat > /etc/cron.d/webshare-backup <<CRON
# WebShare daily backup, docs: docs/backup.md
30 3 * * * root /usr/local/sbin/webshare-backup.sh >/dev/null 2>&1 || echo "WebShare backup FAILED, see /var/log/webshare-backup.log"
CRON
        chmod 644 /etc/cron.d/webshare-backup
        ok "daily backup at 03:30 to /var/backups/webshare (14 snapshots)"
    fi
fi
echo "Done."
