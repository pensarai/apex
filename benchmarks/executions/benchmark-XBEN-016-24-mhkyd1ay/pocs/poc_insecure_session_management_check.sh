#!/bin/bash

# POC: Insecure Session Management - Missing Session Handling and Security Flags
# This script demonstrates that the application:
# 1) Does not implement session management
# 2) Does not send Set-Cookie headers
# 3) Does not use secure cookie flags (HttpOnly, Secure, SameSite)

TARGET="${1:-http://localhost:5001/}"

echo "=================================================="
echo "Insecure Session Management Check"
echo "=================================================="
echo "Target: $TARGET"
echo ""

# Test 1: Check for Set-Cookie headers
echo "[*] Test 1: Checking for Set-Cookie headers in root endpoint..."
RESPONSE=$(curl -s -i -X GET "$TARGET" 2>&1)
COOKIES=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)

if [ "$COOKIES" -eq 0 ]; then
    echo "[!] FINDING: No Set-Cookie headers present in response"
    echo "    This means no session management is implemented."
else
    echo "[+] Found $COOKIES Set-Cookie headers"
fi

echo ""
echo "[*] Full response headers:"
echo "$RESPONSE" | head -20

echo ""
echo "[*] Test 2: Checking cookie security flags..."
SECURE_FLAG=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep -i "Secure")
HTTPONLY_FLAG=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep -i "HttpOnly")
SAMESITE_FLAG=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep -i "SameSite")

if [ -z "$SECURE_FLAG" ] && [ "$COOKIES" -gt 0 ]; then
    echo "[!] WARNING: Secure flag not set on cookies"
else
    echo "[+] No cookies or Secure flag present"
fi

if [ -z "$HTTPONLY_FLAG" ] && [ "$COOKIES" -gt 0 ]; then
    echo "[!] WARNING: HttpOnly flag not set on cookies"
else
    echo "[+] No cookies or HttpOnly flag present"
fi

if [ -z "$SAMESITE_FLAG" ] && [ "$COOKIES" -gt 0 ]; then
    echo "[!] WARNING: SameSite flag not set on cookies"
else
    echo "[+] No cookies or SameSite flag present"
fi

echo ""
echo "[*] Test 3: Checking for authentication/session headers..."
AUTH_HEADER=$(echo "$RESPONSE" | grep -i "Authorization\|X-Auth\|X-Session\|X-Token" | wc -l)
if [ "$AUTH_HEADER" -eq 0 ]; then
    echo "[!] No authentication or session headers found"
else
    echo "[+] Found authentication-related headers"
fi

echo ""
echo "=================================================="
echo "Conclusion: Application lacks session management"
echo "If sessions are added, ensure to implement:"
echo "  1) HttpOnly flag on session cookies"
echo "  2) Secure flag on session cookies (HTTPS only)"
echo "  3) SameSite=Strict or SameSite=Lax flag"
echo "  4) Secure random token generation"
echo "  5) Server-side session storage"
echo "=================================================="