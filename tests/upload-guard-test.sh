#!/usr/bin/env bash
# Upload guard end-to-end test (docs/upload-guard.md)
# Usage: tests/upload-guard-test.sh https://webshare.example.com [target_user]
# Requires: curl, python3. Creates small test files in the Public folder
# (or the target user's folder) and removes them again via the Stop endpoint.
set -u
BASE="${1:?base URL required}"
TARGET="${2:-}"
URL="$BASE/u${TARGET:+/$TARGET}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; echo "        $2"; FAIL=$((FAIL+1)); }
check(){ if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "expected '$3', got: ${2:0:200}"; fi; }

echo "probe-$$-$RANDOM" > "$TMP/guard-test-$$.txt"
echo "<?php echo 1;" > "$TMP/evil-$$.php.txt"
head -c 3000000 /dev/zero > "$TMP/big-$$.bin"

echo "== 1. Page and status"
code=$(curl -sk -o "$TMP/page.html" -w '%{http_code}' "$URL")
check "upload page loads (200)" "$code" "200"
check "page shows verification card" "$(cat "$TMP/page.html")" 'id="guardCard"'
st=$(curl -sk "$URL?guard=status")
check "status says verification required" "$st" '"required":true'

echo "== 2. Rejections without a pass"
code=$(curl -sk -o /dev/null -w '%{http_code}' -F "file=@$TMP/guard-test-$$.txt" "$URL")
check "Apache pre-filter rejects passless POST (403)" "$code" "403"
up=$(curl -sk -o /dev/null -w '%{size_upload}' -F "file=@$TMP/big-$$.bin" "$URL")
if [ "${up%.*}" -lt 1000000 ]; then ok "body not transferred when rejected ($up bytes sent)"; else bad "body not transferred" "sent $up bytes"; fi
out=$(curl -sk -b "ws_upass=00000000000000000000000000000000" -F "file=@$TMP/guard-test-$$.txt" "$URL")
check "PHP rejects fake pass cookie" "$out" "Upload verification required"
out=$(curl -sk -H "X-Upload-Pass: ZZZZ-ZZZZ" -F "file=@$TMP/guard-test-$$.txt" "$URL")
check "PHP rejects unknown code" "$out" "Upload verification required"
out=$(curl -sk -F "delete_partial=guard-test-$$.txt" -H "X-Upload-Pass: ZZZZ-ZZZZ" "$URL")
check "Stop endpoint without pass deletes nothing" "$out" '"success":false'

echo "== 3. Proof-of-work verification"
curl -sk -c "$TMP/jar" -b "$TMP/jar" "$URL?guard=challenge" > "$TMP/ch.json"
python3 - "$TMP/ch.json" > "$TMP/sol.json" <<'PY'
import json, hashlib, sys
ch = json.load(open(sys.argv[1]))
for n in range(ch["maxnumber"] + 1):
    if hashlib.sha256((ch["salt"] + str(n)).encode()).hexdigest() == ch["challenge"]:
        print(json.dumps({"pow": {"algorithm": ch["algorithm"], "challenge": ch["challenge"],
              "salt": ch["salt"], "number": n, "signature": ch["signature"]}}))
        break
PY
bad_sol=$(python3 -c "import json,sys;d=json.load(open('$TMP/sol.json'));d['pow']['number']+=1;print(json.dumps(d))")
out=$(curl -sk -X POST -H 'Content-Type: application/json' -d "$bad_sol" "$URL?guard=verify")
check "wrong answer is rejected" "$out" "wrong_answer"
out=$(curl -sk -c "$TMP/jar" -b "$TMP/jar" -X POST -H 'Content-Type: application/json' -d @"$TMP/sol.json" "$URL?guard=verify")
check "correct answer issues a pass" "$out" '"success":true'
CODE=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['pass']['code'])" "$out" 2>/dev/null)
out=$(curl -sk -X POST -H 'Content-Type: application/json' -d @"$TMP/sol.json" "$URL?guard=verify")
check "same solution cannot be reused" "$out" "replayed"

echo "== 4. Uploads with the pass (code: ${CODE:-none})"
out=$(curl -sk -H "X-Upload-Pass: $CODE" -F "file=@$TMP/guard-test-$$.txt" "$URL")
check "curl upload with code succeeds" "$out" "OK: uploaded as"
FINAL=$(echo "$out" | sed -n 's/^OK: uploaded as \([^ ]*\).*/\1/p')
out=$(curl -sk -b "$TMP/jar" -H 'X-Requested-With: XMLHttpRequest' -F "file=@$TMP/guard-test-$$.txt" "$URL")
check "browser-style upload with cookie succeeds" "$out" '"success":true'
check "response reports remaining quota" "$out" '"files_left"'
FINAL2=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['finalName'])" "$out" 2>/dev/null)
out=$(curl -sk -H "X-Upload-Pass: $CODE" -F "file=@$TMP/evil-$$.php.txt" "$URL")
check "script file is blocked" "$out" "not allowed"

echo "== 5. Stop endpoint is bound to the pass"
out=$(curl -sk -H "X-Upload-Pass: $CODE" -F "delete_partial=$FINAL" "$URL")
check "own recent upload can be removed" "$out" '"success":true'
out=$(curl -sk -H "X-Upload-Pass: $CODE" -F "delete_partial=$FINAL2" "$URL")
check "second own upload can be removed" "$out" '"success":true'
out=$(curl -sk -H "X-Upload-Pass: $CODE" -F "delete_partial=README.md" "$URL")
check "foreign file name is not removed" "$out" '"success":false'

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
