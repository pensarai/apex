#!/bin/bash
# POC: Demonstrates that multiple concurrent sessions can be created for the same user account without any limitations, and all sessions remain valid simultaneously
# Target: ./repo
# Created: 2025-10-31T17:21:45.819Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "=================================================="
echo "POC: Unlimited Concurrent Sessions Vulnerability"
echo "=================================================="
echo ""

TARGET="http://localhost:8080"
USERNAME="john"
PASSWORD="password123"

echo "[*] Testing unlimited concurrent sessions for user: $USERNAME"
echo ""

# Create Session 1
echo "[1] Creating Session 1..."
RESPONSE1=$(curl -s -i -X POST "$TARGET/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -c /tmp/cookies1.txt)

SESSION1=$(echo "$RESPONSE1" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r')

if [ -z "$SESSION1" ]; then
  echo "[-] Failed to create Session 1"
  exit 1
fi

echo "[+] Session 1 created: ${SESSION1:0:50}..."
echo ""

# Test Session 1
echo "[2] Testing Session 1 access to dashboard..."
STATUS1=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION1")

if [ "$STATUS1" = "200" ]; then
  echo "[+] Session 1 works: HTTP $STATUS1"
else
  echo "[-] Session 1 failed: HTTP $STATUS1"
  exit 1
fi
echo ""

# Wait 2 seconds
echo "[3] Waiting 2 seconds before creating Session 2..."
sleep 2
echo ""

# Create Session 2 (same user)
echo "[4] Creating Session 2 for same user..."
RESPONSE2=$(curl -s -i -X POST "$TARGET/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -c /tmp/cookies2.txt)

SESSION2=$(echo "$RESPONSE2" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r')

if [ -z "$SESSION2" ]; then
  echo "[-] Failed to create Session 2"
  exit 1
fi

echo "[+] Session 2 created: ${SESSION2:0:50}..."
echo ""

# Verify sessions are different
if [ "$SESSION1" = "$SESSION2" ]; then
  echo "[-] ERROR: Sessions are identical (unexpected)"
  exit 1
else
  echo "[+] Sessions have different tokens (expected)"
fi
echo ""

# Test Session 2
echo "[5] Testing Session 2 access to dashboard..."
STATUS2=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION2")

if [ "$STATUS2" = "200" ]; then
  echo "[+] Session 2 works: HTTP $STATUS2"
else
  echo "[-] Session 2 failed: HTTP $STATUS2"
  exit 1
fi
echo ""

# Critical Test: Verify Session 1 still works after Session 2 was created
echo "[6] CRITICAL TEST: Does Session 1 still work after Session 2 was created?"
STATUS1_AFTER=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION1")

echo "[*] Session 1 status after Session 2 creation: HTTP $STATUS1_AFTER"

if [ "$STATUS1_AFTER" = "200" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Session 1 still valid after Session 2 created"
  echo "[!] Both sessions work concurrently without invalidation"
else
  echo "[+] Session 1 was invalidated (secure behavior)"
  exit 1
fi
echo ""

# Create Session 3 to test for limits
echo "[7] Creating Session 3 to test for session limits..."
RESPONSE3=$(curl -s -i -X POST "$TARGET/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -c /tmp/cookies3.txt)

SESSION3=$(echo "$RESPONSE3" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r')

if [ -z "$SESSION3" ]; then
  echo "[-] Failed to create Session 3"
  exit 1
fi

echo "[+] Session 3 created: ${SESSION3:0:50}..."

STATUS3=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION3")

echo "[+] Session 3 works: HTTP $STATUS3"
echo ""

# Final verification: All 3 sessions work concurrently
echo "[8] FINAL VERIFICATION: Testing all 3 sessions concurrently..."
STATUS1_FINAL=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" -H "Cookie: session=$SESSION1")
STATUS2_FINAL=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" -H "Cookie: session=$SESSION2")
STATUS3_FINAL=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/dashboard" -H "Cookie: session=$SESSION3")

echo "[*] Session 1: HTTP $STATUS1_FINAL"
echo "[*] Session 2: HTTP $STATUS2_FINAL"
echo "[*] Session 3: HTTP $STATUS3_FINAL"
echo ""

if [ "$STATUS1_FINAL" = "200" ] && [ "$STATUS2_FINAL" = "200" ] && [ "$STATUS3_FINAL" = "200" ]; then
  echo "=========================================="
  echo "VULNERABILITY CONFIRMED"
  echo "=========================================="
  echo "All 3 concurrent sessions remain valid"
  echo "No session limit detected"
  echo "No session invalidation on new login"
  echo "User '$USERNAME' has 3+ active sessions simultaneously"
  echo ""
  echo "IMPACT: Unlimited concurrent sessions allowed"
  echo "=========================================="
  exit 0
else
  echo "[*] Some sessions were invalidated (session limit may exist)"
  exit 1
fi

# Cleanup
rm -f /tmp/cookies1.txt /tmp/cookies2.txt /tmp/cookies3.txt 2>/dev/null