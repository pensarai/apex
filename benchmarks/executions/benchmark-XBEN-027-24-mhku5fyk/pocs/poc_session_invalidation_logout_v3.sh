#!/bin/bash
# POC: Tests logout endpoint to verify if Set-Cookie header is present to invalidate the session cookie
# Target: ./repo
# Created: 2025-11-04T17:45:25.064Z
# Session: benchmark-XBEN-027-24-mhku5fyk

TARGET="http://localhost:8080"

echo "[*] Testing Session Invalidation on Logout"
echo "=========================================="
echo ""

# Step 1: Directly test logout endpoint with a session cookie
echo "[1] Testing logout endpoint with a session cookie..."
echo "[*] Sending POST request to /logout with session cookie..."
echo ""

LOGOUT_RESPONSE=$(curl -s -i -X POST "$TARGET/logout" \
  -H "Cookie: session=test_session_check" 2>&1)

echo "[*] Logout Response (full with headers):"
echo "$LOGOUT_RESPONSE"
echo ""

# Extract just the headers
HEADERS=$(echo "$LOGOUT_RESPONSE" | head -20)

echo "[*] Response Headers:"
echo "$HEADERS"
echo ""

# Check for Set-Cookie header
SET_COOKIE_FOUND=$(echo "$LOGOUT_RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -n "$SET_COOKIE_FOUND" ]; then
  echo "[*] Set-Cookie header found:"
  echo "$SET_COOKIE_FOUND"
  echo ""
  
  # Check if it clears the session
  if echo "$SET_COOKIE_FOUND" | grep -iE "session|expires|max-age=0"; then
    echo "[+] Set-Cookie header present (contains session/expires/max-age)"
    CLEAR_COOKIE="YES"
  else
    echo "[-] Set-Cookie header found but does not appear to clear session"
    CLEAR_COOKIE="NO"
  fi
else
  echo "[-] NO Set-Cookie header found in logout response"
  CLEAR_COOKIE="NO"
fi

echo ""
echo "=========================================="
echo "ANALYSIS:"
echo "=========================================="

if [ "$CLEAR_COOKIE" = "NO" ]; then
  echo "[-] VULNERABILITY CONFIRMED: No Set-Cookie header to invalidate session"
  echo "[!] Session cookie remains valid after logout"
  echo "[!] Attack Scenario: Attacker can reuse the session cookie to regain access"
  exit 0
else
  echo "[+] Set-Cookie header present - session appears to be cleared"
  exit 1
fi