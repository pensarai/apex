#!/bin/bash

# POC: No Session Invalidation on Concurrent Login
# This script demonstrates that an application allows multiple concurrent active sessions
# for the same user. When a user logs in again, the previous session is NOT invalidated.

set -e

TARGET_URL="${TARGET_URL:-http://localhost:5003}"
USERNAME="admin"
PASSWORD="!@ED#"
PROTECTED_ENDPOINT="/add_prescription"

echo "[*] Testing Concurrent Session Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Create first session
echo "[1] Creating first session..."
RESPONSE1=$(curl -s -c /tmp/session_1.txt -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

echo "    Response: $RESPONSE1"
SESSION_1=$(grep session /tmp/session_1.txt | awk '{print $7}')
echo "    Session 1 Token: $SESSION_1"
echo ""

# Test 2: Verify Session 1 is active
echo "[2] Verifying Session 1 is active on protected endpoint..."
HTTP_CODE1=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION_1" "$TARGET_URL$PROTECTED_ENDPOINT")
echo "    HTTP Response Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ]; then
    echo "    ✓ Session 1 is ACTIVE and valid"
else
    echo "    ✗ Session 1 failed with HTTP $HTTP_CODE1"
    exit 1
fi
echo ""

# Test 3: Create second session (same user, without logging out)
echo "[3] Creating second session WITHOUT logging out from first..."
RESPONSE2=$(curl -s -c /tmp/session_2.txt -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

echo "    Response: $RESPONSE2"
SESSION_2=$(grep session /tmp/session_2.txt | awk '{print $7}')
echo "    Session 2 Token: $SESSION_2"
echo ""

# Test 4: Verify Session 2 is active
echo "[4] Verifying Session 2 is active on protected endpoint..."
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION_2" "$TARGET_URL$PROTECTED_ENDPOINT")
echo "    HTTP Response Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "    ✓ Session 2 is ACTIVE and valid"
else
    echo "    ✗ Session 2 failed with HTTP $HTTP_CODE2"
    exit 1
fi
echo ""

# Test 5: Verify Session 1 is STILL active (concurrent with Session 2)
echo "[5] Verifying Session 1 is STILL ACTIVE (concurrently with Session 2)..."
HTTP_CODE1_AGAIN=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION_1" "$TARGET_URL$PROTECTED_ENDPOINT")
echo "    HTTP Response Code: $HTTP_CODE1_AGAIN"
if [ "$HTTP_CODE1_AGAIN" = "200" ]; then
    echo "    ✓ Session 1 REMAINS ACTIVE even after Session 2 created"
    echo "    ✗ VULNERABILITY CONFIRMED: Multiple concurrent sessions allowed!"
else
    echo "    ✓ Session 1 was invalidated (expected behavior)"
    exit 1
fi
echo ""

# Test 6: Verify both sessions work simultaneously
echo "[6] Testing both sessions work simultaneously..."
echo "    Attempting simultaneous requests..."

RESPONSE_S1=$(curl -s -b "session=$SESSION_1" "$TARGET_URL$PROTECTED_ENDPOINT" | head -c 50)
RESPONSE_S2=$(curl -s -b "session=$SESSION_2" "$TARGET_URL$PROTECTED_ENDPOINT" | head -c 50)

echo "    Session 1 response (first 50 chars): $RESPONSE_S1"
echo "    Session 2 response (first 50 chars): $RESPONSE_S2"
echo ""

echo "[✓] VULNERABILITY CONFIRMED: Concurrent Sessions Not Invalidated"
echo "    - Session 1 created and verified as active"
echo "    - Session 2 created WITHOUT logging out from Session 1"
echo "    - Session 1 remains active concurrently with Session 2"
echo "    - Both sessions are simultaneously valid"
echo "    - New login did NOT invalidate previous sessions"
echo ""
echo "[!] Impact: Attacker with captured session token can maintain access"
echo "           even if legitimate user logs in from another device."