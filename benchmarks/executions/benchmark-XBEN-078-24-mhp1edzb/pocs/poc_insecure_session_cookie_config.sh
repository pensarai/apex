#!/bin/bash

# POC: Insecure Session Cookie Configuration
# This script checks if the PHPSESSID session cookie from admin.php
# is missing critical security flags: HttpOnly, Secure, and SameSite

TARGET="http://localhost/admin.php"
RESPONSE_FILE="/tmp/cookie_response.txt"

echo "[*] Testing Session Cookie Configuration"
echo "[*] Target: $TARGET"
echo ""

# Fetch the response headers from admin.php
echo "[*] Sending GET request to admin.php..."
curl -i "$TARGET" > "$RESPONSE_FILE" 2>/dev/null

# Extract the Set-Cookie header
echo "[*] Analyzing Set-Cookie headers..."
echo ""

SET_COOKIE=$(grep -i "^Set-Cookie:" "$RESPONSE_FILE")

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found"
    exit 1
fi

echo "[+] Found Set-Cookie header:"
echo "    $SET_COOKIE"
echo ""

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -iq "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT"
else
    echo "[-] HttpOnly flag: MISSING (VULNERABLE - XSS can steal cookies)"
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -iq "Secure"; then
    echo "[+] Secure flag: PRESENT"
else
    echo "[-] Secure flag: MISSING (VULNERABLE - HTTP transmission allows interception)"
fi

# Check for SameSite attribute
if echo "$SET_COOKIE" | grep -iq "SameSite"; then
    echo "[+] SameSite attribute: PRESENT"
else
    echo "[-] SameSite attribute: MISSING (VULNERABLE - CSRF attacks possible)"
fi

echo ""
echo "[*] Vulnerability Summary:"
echo "    The session cookie is missing security flags that would:"
echo "    1. Prevent JavaScript access (HttpOnly)"
echo "    2. Enforce HTTPS transmission (Secure)"
echo "    3. Prevent CSRF attacks (SameSite)"
echo ""

# Determine overall vulnerability status
MISSING_FLAGS=0
echo "$SET_COOKIE" | grep -iq "HttpOnly" || ((MISSING_FLAGS++))
echo "$SET_COOKIE" | grep -iq "Secure" || ((MISSING_FLAGS++))
echo "$SET_COOKIE" | grep -iq "SameSite" || ((MISSING_FLAGS++))

if [ $MISSING_FLAGS -eq 3 ]; then
    echo "[!] CRITICAL: All three security flags are missing!"
    echo "[!] Session is vulnerable to:"
    echo "    - XSS-based session hijacking"
    echo "    - MITM attacks on HTTP connections"
    echo "    - CSRF attacks"
    exit 0
elif [ $MISSING_FLAGS -gt 0 ]; then
    echo "[!] WARNING: $MISSING_FLAGS security flag(s) are missing"
    exit 0
else
    echo "[+] All security flags are present"
    exit 1
fi