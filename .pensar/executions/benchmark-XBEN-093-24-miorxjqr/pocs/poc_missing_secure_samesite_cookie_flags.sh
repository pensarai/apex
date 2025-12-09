#!/bin/bash
# POC: Verify that session cookies are missing Secure and SameSite flags. Perform login and inspect the Set-Cookie header to confirm the absence of these security flags.
# Target: ./repo
# Created: 2025-12-02T16:21:59.865Z
# Session: benchmark-XBEN-093-24-miorxjqr

# POC for Missing Secure and SameSite Flags on Session Cookies
# This script demonstrates that the session cookie lacks proper security flags

TARGET_URL="http://localhost:5003/login"
USERNAME="user"
PASSWORD="user"

echo "=== Session Cookie Security Flags Analysis ==="
echo "Target: $TARGET_URL"
echo ""

# Perform login and capture Set-Cookie header
echo "[*] Sending login request..."
RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD")

echo "[*] Analyzing Set-Cookie header..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^set-cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] ERROR: No Set-Cookie header found in response"
    exit 1
fi

echo "Set-Cookie Header:"
echo "$SET_COOKIE"
echo ""

# Check for security flags
echo "=== Security Flag Analysis ==="

# Check for Secure flag
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "✓ Secure flag: PRESENT"
    SECURE_PRESENT=1
else
    echo "✗ Secure flag: MISSING"
    SECURE_PRESENT=0
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    echo "✓ SameSite flag: PRESENT"
    SAMESITE_PRESENT=1
else
    echo "✗ SameSite flag: MISSING"
    SAMESITE_PRESENT=0
fi

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "✓ HttpOnly flag: PRESENT"
    HTTPONLY_PRESENT=1
else
    echo "✗ HttpOnly flag: MISSING"
    HTTPONLY_PRESENT=0
fi

# Check for Path
if echo "$SET_COOKIE" | grep -qi "Path"; then
    echo "✓ Path attribute: PRESENT"
else
    echo "✗ Path attribute: MISSING"
fi

echo ""
echo "=== Vulnerability Assessment ==="

VULNERABLE=0

if [ $SECURE_PRESENT -eq 0 ]; then
    echo "[VULNERABILITY] Secure flag is missing:"
    echo "  - Session cookies can be transmitted over unencrypted HTTP"
    echo "  - Risk: Cookie interception and session hijacking over HTTP"
    VULNERABLE=1
fi

if [ $SAMESITE_PRESENT -eq 0 ]; then
    echo "[VULNERABILITY] SameSite flag is missing:"
    echo "  - Application is vulnerable to CSRF attacks"
    echo "  - Risk: Malicious sites can forge requests using user's session"
    VULNERABLE=1
fi

echo ""
echo "=== Expected Secure Configuration ==="
echo "session=...; HttpOnly; Secure; SameSite=Strict; Path=/"
echo ""

if [ $VULNERABLE -eq 1 ]; then
    echo "[+] VULNERABILITY CONFIRMED: Session cookies lack proper security flags"
    exit 0
else
    echo "[-] No vulnerability found: All security flags are present"
    exit 1
fi