#!/usr/bin/env bash
# PSK history diagnostic: verifies code/git state and runs the full rotation flow.
# Usage: ./psk_diag.sh   (prompts for host and token)

set -u

echo "==================== 0. INPUT ===================="
read -r -p "PKI server base URL [http://localhost]: " HOST
HOST=${HOST:-http://localhost}
HOST=${HOST%/}
read -r -p "API token: " TOKEN
if [ -z "$TOKEN" ]; then echo "ERROR: token is required"; exit 1; fi

CURL="curl -s -k"

echo
echo "==================== 1. REPO / CODE STATE ===================="
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "--- repo root: $(git rev-parse --show-toplevel)"
    echo "--- branch:    $(git branch --show-current)"
    echo "--- last commit:"
    git log --oneline -3
    echo "--- status (should be clean):"
    git status --short || true
else
    echo "WARNING: not inside a git repo (cd to the pikachu-ca checkout first)"
fi

echo
echo "--- X-PSK-Fingerprint present in enterprise/preshared_keys.py?"
grep -n "X-PSK-Fingerprint" enterprise/preshared_keys.py 2>/dev/null || echo "NOT FOUND  <-- code on disk is OLD"

echo
echo "--- history routes present in app.py?"
grep -n "history/<hash_id>" app.py 2>/dev/null || echo "NOT FOUND  <-- code on disk is OLD"

echo
echo "--- in-memory history store present?"
grep -n "_PSK_HISTORY" enterprise/preshared_keys.py 2>/dev/null | head -3 || echo "NOT FOUND  <-- runtime-only history change missing"

echo
echo "==================== 2. RUNNING PROCESS ===================="
echo "--- python processes running app.py (check START time is AFTER the git pull):"
ps -eo pid,lstart,cmd | grep -E "[p]ython.*app\.py" || echo "no app.py process found (server may run differently)"

echo
echo "==================== 3. API FLOW ===================="
NAME="psk-diag-$(date +%H%M%S)"

echo "--- 3.1 CREATE $NAME"
$CURL -X POST "$HOST/api/preshared_keys" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$NAME\",\"rotation_interval\":\"1h\"}"
echo

echo
echo "--- 3.2 GET by name (headers + body)"
$CURL -i "$HOST/api/preshared_keys/$NAME" -H "Authorization: Bearer $TOKEN"
echo

FP1=$($CURL -D - -o /dev/null "$HOST/api/preshared_keys/$NAME" -H "Authorization: Bearer $TOKEN" \
    | grep -i '^x-psk-fingerprint:' | tail -1 | tr -d '\r' | awk '{print $2}')
echo
echo "--- extracted FP1='$FP1'"
if [ -z "$FP1" ]; then
    echo "ERROR: no X-PSK-Fingerprint header returned - server is running old code. Stopping."
    exit 1
fi

echo
echo "--- 3.3 ROTATE"
$CURL -X POST "$HOST/api/preshared_keys/$NAME/rotation/start" -H "Authorization: Bearer $TOKEN"
echo

VAL2=$($CURL "$HOST/api/preshared_keys/$NAME" -H "Authorization: Bearer $TOKEN")
FP2=$($CURL -D - -o /dev/null "$HOST/api/preshared_keys/$NAME" -H "Authorization: Bearer $TOKEN" \
    | grep -i '^x-psk-fingerprint:' | tail -1 | tr -d '\r' | awk '{print $2}')
echo
echo "--- 3.4 GET after rotation: FP2='$FP2' value='$VAL2'"

echo
echo "--- 3.5 ROTATE AGAIN"
$CURL -X POST "$HOST/api/preshared_keys/$NAME/rotation/start" -H "Authorization: Bearer $TOKEN"
echo

echo
echo "--- 3.6 HISTORY LIST"
$CURL "$HOST/api/preshared_keys/$NAME/history" -H "Authorization: Bearer $TOKEN"
echo

echo
echo "--- 3.7 GET PREVIOUS VALUE BY HASH ($FP2)"
$CURL -i "$HOST/api/preshared_keys/$NAME/history/$FP2" -H "Authorization: Bearer $TOKEN"
echo

VAL_BYHASH=$($CURL "$HOST/api/preshared_keys/$NAME/history/$FP2" -H "Authorization: Bearer $TOKEN")
echo
echo "==================== 4. RESULT ===================="
if [ "$VAL_BYHASH" = "$VAL2" ]; then
    echo "PASS: previous value retrieved by hash matches the pre-rotation value"
else
    echo "FAIL: mismatch"
    echo "  expected: $VAL2"
    echo "  got:      $VAL_BYHASH"
fi

echo
echo "--- cleanup: deleting $NAME"
$CURL -X DELETE "$HOST/api/preshared_keys/$NAME" -H "Authorization: Bearer $TOKEN"
echo
echo "Done."
