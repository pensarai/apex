#!/bin/bash

# POC: Missing Security Flags on JWT Authentication Cookie
# This script demonstrates that the JWT authentication cookie is missing:
# 1. HttpOnly flag (allows XSS to steal the token)
# 2. Secure flag (allows MITM on non-HTTPS)
# 3. SameSite flag (allows CSRF attacks)

TARGET="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "=== Testing Missing JWT Cookie Security Flags ==="
echo ""
echo "[*] Target: $TARGET$LOGIN_ENDPOINT"
echo "[*] Attempting login and checking Set-Cookie header..."
echo ""

# Perform login and capture response headers
RESPONSE=$(curl -v -X POST "$TARGET$LOGIN_ENDPOINT" \
  -d "username=user&password=user" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^< set-cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found"
    exit 1
fi

echo "[+] Set-Cookie header found:"
echo "    $SET_COOKIE"
echo ""

# Check for security flags
echo "[*] Security Flag Analysis:"
echo ""

if echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
    echo "    [+] HttpOnly flag: PRESENT"
    HTTPONLY_PRESENT=1
else
    echo "    [-] HttpOnly flag: MISSING (XSS can steal token)"
    HTTPONLY_PRESENT=0
fi

if echo "$SET_COOKIE" | grep -iq "Secure"; then
    echo "    [+] Secure flag: PRESENT"
    SECURE_PRESENT=1
else
    echo "    [-] Secure flag: MISSING (MITM can intercept token)"
    SECURE_PRESENT=0
fi

if echo "$SET_COOKIE" | grep -iq "SameSite"; then
    echo "    [+] SameSite flag: PRESENT"
    SAMESITE_PRESENT=1
else
    echo "    [-] SameSite flag: MISSING (CSRF can send cookie)"
    SAMESITE_PRESENT=0
fi

echo ""

# Summary
TOTAL_FLAGS=3
MISSING_FLAGS=$((3 - HTTPONLY_PRESENT - SECURE_PRESENT - SAMESITE_PRESENT))

if [ $MISSING_FLAGS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "    $MISSING_FLAGS out of $TOTAL_FLAGS security flags are missing"
    echo ""
    echo "[!] Risk Assessment:"
    if [ $HTTPONLY_PRESENT -eq 0 ]; then
        echo "    - XSS attacks can steal the JWT token via JavaScript"
    fi
    if [ $SECURE_PRESENT -eq 0 ]; then
        echo "    - Token can be intercepted in transit if HTTPS is not enforced"
    fi
    if [ $SAMESITE_PRESENT -eq 0 ]; then
        echo "    - Token can be sent to other sites (CSRF risk)"
    fi
    exit 0
else
    echo "[-] No vulnerability detected - all security flags are present"
    exit 1
fi