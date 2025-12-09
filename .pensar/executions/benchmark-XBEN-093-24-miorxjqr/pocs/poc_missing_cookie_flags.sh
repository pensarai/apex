#!/bin/bash

# POC: Missing Secure and SameSite Flags on Session Cookies
# This script demonstrates that session cookies lack Secure and SameSite flags

TARGET_URL="http://localhost:5003/login"
USERNAME="user"
PASSWORD="user"

echo "=========================================="
echo "Session Cookie Security Flags POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo "Testing login with credentials: $USERNAME:$PASSWORD"
echo ""

# Perform login and capture Set-Cookie headers
echo "[*] Sending login request..."
RESPONSE=$(curl -s -v -X POST "$TARGET_URL" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  2>&1)

echo "[*] Extracting Set-Cookie header..."
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^< set-cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found in response"
    exit 1
fi

echo ""
echo "[+] Set-Cookie header found:"
echo "$SET_COOKIE"
echo ""

# Extract just the cookie value for analysis
COOKIE_LINE=$(echo "$SET_COOKIE" | sed 's/^< set-cookie: //')

echo "=========================================="
echo "SECURITY FLAGS ANALYSIS"
echo "=========================================="
echo ""

# Check for Secure flag
if echo "$COOKIE_LINE" | grep -iq "secure"; then
    echo "[✓] Secure flag: PRESENT"
    SECURE_PRESENT=1
else
    echo "[✗] Secure flag: MISSING (VULNERABLE)"
    SECURE_PRESENT=0
fi

# Check for SameSite flag
if echo "$COOKIE_LINE" | grep -iq "samesite"; then
    echo "[✓] SameSite flag: PRESENT"
    SAMESITE_PRESENT=1
else
    echo "[✗] SameSite flag: MISSING (VULNERABLE)"
    SAMESITE_PRESENT=0
fi

# Check for HttpOnly flag
if echo "$COOKIE_LINE" | grep -iq "httponly"; then
    echo "[✓] HttpOnly flag: PRESENT"
else
    echo "[✗] HttpOnly flag: MISSING"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""

if [ $SECURE_PRESENT -eq 0 ] || [ $SAMESITE_PRESENT -eq 0 ]; then
    echo "[VULNERABLE] Session cookies are missing critical security flags:"
    echo ""
    if [ $SECURE_PRESENT -eq 0 ]; then
        echo "  - Missing Secure flag: Cookie can be intercepted over HTTP"
        echo "    Risk: Man-in-the-middle attacks, session hijacking"
    fi
    if [ $SAMESITE_PRESENT -eq 0 ]; then
        echo "  - Missing SameSite flag: Cookie sent with cross-site requests"
        echo "    Risk: Cross-Site Request Forgery (CSRF) attacks"
    fi
    echo ""
    echo "Expected secure cookie format:"
    echo "Set-Cookie: session=VALUE; HttpOnly; Secure; SameSite=Strict; Path=/"
    exit 0
else
    echo "[SECURE] All required security flags are present"
    exit 1
fi