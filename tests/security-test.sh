#!/bin/bash
# End-to-end checks for the security hardening (U2-U11), docs/security-hardening.md
# Run as root ON the server, from an address in the fail2ban ignoreip list
# (the U7 check makes 11 failed attempts on purpose):
#   tests/security-test.sh https://webshare.techbg.net
# Creates a temporary API key and folder share and removes them afterwards.
set -u
URL=${1:?usage: $0 https://host}
SRC=$(cd "$(dirname "$0")/../src" && pwd)
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }
asw()  { (cd "$SRC" && runuser -u www-data -- php -r "$1"); }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "U5 internal files are not served"
for f in README.md README-BG.md SECURITY-AUDIT.md GeoLite2-Country.mmdb x.php.bak x.php~ x.php.bak-20260101 .users.json .auth-attempts.json; do
    check "$f -> 403/404" "$(code "$URL/$f" | sed 's/404/403/')" 403
done
for f in CHANGELOG.md version.json htaccess.txt user.ini.txt robots.txt ui-kit.css; do
    check "$f still public (updates need it)" "$(code "$URL/$f")" 200
done

echo "U11 search engines"
check "robots.txt disallows all" "$(curl -sk "$URL/robots.txt" | grep -c '^Disallow: /$')" 1
check "X-Robots-Tag on /u" "$(curl -skI "$URL/u" | grep -ci '^x-robots-tag: noindex')" 1

echo "U4 update channel endpoint"
check "anonymous POST does not reach the handler" "$(curl -sk -X POST "$URL/index.php?action=set_update_source" -d use_beta=1 | grep -c '"success":true')" 0
check "no call to the missing validateCsrfToken()" "$(grep -c 'validateCsrfToken' "$SRC/index.php")" 0

echo "U2 login redirect"
check "login page with //evil.com still renders" "$(code "$URL/login.php?redirect=//evil.com")" 200
check "login.php uses ws_safe_redirect for every redirect" "$(grep -c "\$_GET\['redirect'\]" "$SRC/login.php")" "$(grep -c "ws_safe_redirect(\$_GET\['redirect'\]" "$SRC/login.php")"

echo "U3 API upload with encryption"
KEY=$(asw 'require "user-management.php"; $k = generateApiKey("admin", "security-test"); echo $k["id"], " ", $k["key"];')
KID=${KEY%% *}; KVAL=${KEY#* }
echo "secret content $$" > "$TMP/enc-test-$$.txt"
R=$(curl -sk -H "X-API-Key: $KVAL" -F "file=@$TMP/enc-test-$$.txt" -F encrypt=1 -F encrypt_password=test1234 "$URL/api-upload.php")
NAME=$(echo "$R" | php -r '$r=json_decode(stream_get_contents(STDIN),true); echo $r["filename"] ?? $r["file"] ?? "";')
check "upload succeeds" "$(echo "$R" | grep -c '"success":true')" 1
check "stored name ends in .enc" "${NAME##*.}" enc
check "encrypted file exists" "$( [ -f "$SRC/files/admin/$NAME" ] && echo 1 || echo 0)" 1
check "plain file was removed" "$( [ -f "$SRC/files/admin/${NAME%.enc}" ] && echo 1 || echo 0)" 0
check "decrypts back to the original" "$(asw "require 'encryption.php'; \$r = decryptFile('files/admin/$NAME', 'test1234'); echo \$r['data'] ?? '';")" "secret content $$"
asw "require 'user-management.php'; require 'encryption.php';
     @unlink('files/admin/$NAME'); revokeApiKey('admin', '$KID');
     \$m = loadFilesMeta(); unset(\$m['admin/$NAME']); saveFilesMeta(\$m);
     \$k = json_decode(file_get_contents('.encryption-keys.json'), true) ?: []; unset(\$k['$NAME']);
     file_put_contents('.encryption-keys.json', json_encode(\$k, JSON_PRETTY_PRINT));"
check "test key revoked (401/403)" "$(code -H "X-API-Key: $KVAL" -F "file=@$TMP/enc-test-$$.txt" "$URL/api-upload.php" | sed s/401/403/)" 403

echo "U7 folder share password limit"
TOK="sectest$$"
asw "\$f='.folder-shares.json'; \$d=json_decode(file_get_contents(\$f),true)?:[];
     \$d['$TOK']=['folder'=>'admin','password'=>password_hash('right',PASSWORD_DEFAULT),'allow_upload'=>false,'allow_delete'=>false,'created'=>time(),'created_by'=>'security-test','expires'=>null,'views'=>0];
     file_put_contents(\$f,json_encode(\$d,JSON_PRETTY_PRINT));"
for i in $(seq 1 10); do curl -sk -o /dev/null -c "$TMP/c" -b "$TMP/c" -d password=wrong "$URL/f/$TOK"; done
check "11th attempt is locked" "$(curl -sk -c "$TMP/c" -b "$TMP/c" -d password=right "$URL/f/$TOK" | grep -c 'Твърде много грешни опити')" 1
check "fail2ban log line written" "$( [ "$(grep -c 'where=share-password' /var/log/fpm-php.webshare.log)" -ge 10 ] && echo 1 || echo 0)" 1
asw "\$f='.folder-shares.json'; \$d=json_decode(file_get_contents(\$f),true); unset(\$d['$TOK']); file_put_contents(\$f,json_encode(\$d,JSON_PRETTY_PRINT));
     require 'auth-guard.php'; \$a=json_decode(@file_get_contents(WS_AUTH_ATTEMPTS_FILE),true)?:[];
     foreach (\$a as \$k=>\$v) if (strpos(\$k,'share-password|')===0) unset(\$a[\$k]); file_put_contents(WS_AUTH_ATTEMPTS_FILE,json_encode(\$a));"

echo "U6 fail2ban"
if command -v fail2ban-client >/dev/null; then
    check "jail webshare reads the PHP log" "$(fail2ban-client status webshare | grep -c fpm-php.webshare.log)" 1
fi

echo "U9 permissions"
for f in "$SRC/.users.json" "$SRC/../.encryption-keys.json" "$SRC/../.folder-shares.json"; do
    check "$(basename "$f") is 600" "$(stat -c %a "$(readlink -f "$f")")" 600
done
check "project dir not world-readable" "$(stat -c %a "$SRC/..")" 750

echo "U10 backup"
check "backup cron installed" "$( [ -f /etc/cron.d/webshare-backup ] && echo 1 || echo 0)" 1
check "last backup younger than 2 days" "$(php -r '$j=json_decode(@file_get_contents("/var/backups/webshare/last.json"),true); echo (($j["time"]??0) > time()-172800) ? 1 : 0;')" 1

echo; echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
