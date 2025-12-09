#!/bin/bash

# POC: Missing Secure Flag on CAPTCHA Cookie
# This script demonstrates that the CAPTCHA cookie lacks security flags (Secure, HttpOnly, SameSite)

echo "=========================================="
echo "POC: Missing Security Flags on CAPTCHA Cookie"
echo "=========================================="
echo ""

# Target URL - adjust if needed
TARGET_URL="${1:-http://localhost:8000/}"

echo "[*] Sending HTTP request to: $TARGET_URL"
echo ""

# Make the request and capture headers
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "[*] Checking for CAPTCHA cookie in Set-Cookie headers..."
echo ""

# Extract Set-Cookie headers
CAPTCHA_COOKIE=$(echo "$RESPONSE" | grep -i 'set-cookie.*captcha' | head -1)

if [ -z "$CAPTCHA_COOKIE" ]; then
    echo "[-] CAPTCHA cookie not found in response headers"
    echo ""
    echo "All Set-Cookie headers found:"
    echo "$RESPONSE" | grep -i 'set-cookie'
    exit 1
fi

echo "[+] CAPTCHA Cookie Found:"
echo "$CAPTCHA_COOKIE"
echo ""

# Check for security flags
echo "[*] Analyzing security flags..."
echo ""

MISSING_FLAGS=0

# Check for Secure flag
if echo "$CAPTCHA_COOKIE" | grep -qi "Secure"; then
    echo "[+] Secure flag: PRESENT"
else
    echo "[-] Secure flag: MISSING (Vulnerability!)"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

# Check for HttpOnly flag
if echo "$CAPTCHA_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT"
else
    echo "[-] HttpOnly flag: MISSING (Vulnerability!)"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

# Check for SameSite attribute
if echo "$CAPTCHA_COOKIE" | grep -qi "SameSite"; then
    echo "[+] SameSite attribute: PRESENT"
else
    echo "[-] SameSite attribute: MISSING (Vulnerability!)"
    MISSING_FLAGS=$((MISSING_FLAGS + 1))
fi

echo ""
echo "=========================================="

if [ $MISSING_FLAGS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "    $MISSING_FLAGS security flags are missing"
    echo ""
    echo "[*] RECOMMENDED FIX:"
    echo "    Set-Cookie: captcha=<value>; Path=/; Secure; HttpOnly; SameSite=Strict"
    echo ""
    exit 0
else
    echo "[✓] All security flags are present"
    echo ""
    exit 1
fi