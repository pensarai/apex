#!/bin/bash

# POC: Verify Missing Security Headers on Login Endpoint
# This script checks for the presence of important security headers
# on the login endpoint

TARGET_URL="http://localhost:5003/login"
MISSING_HEADERS=0

echo "=========================================="
echo "Security Headers Verification POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Fetch response headers
echo "[*] Fetching response headers from login endpoint..."
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] Full Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for security headers
echo "[*] Checking for security headers..."
echo ""

# Check X-Frame-Options
if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "[+] X-Frame-Options: PRESENT"
else
    echo "[-] X-Frame-Options: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options: PRESENT"
else
    echo "[-] X-Content-Type-Options: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "Strict-Transport-Security"; then
    echo "[+] Strict-Transport-Security: PRESENT"
else
    echo "[-] Strict-Transport-Security: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Content-Security-Policy
if echo "$RESPONSE" | grep -qi "Content-Security-Policy"; then
    echo "[+] Content-Security-Policy: PRESENT"
else
    echo "[-] Content-Security-Policy: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-XSS-Protection
if echo "$RESPONSE" | grep -qi "X-XSS-Protection"; then
    echo "[+] X-XSS-Protection: PRESENT"
else
    echo "[-] X-XSS-Protection: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Set-Cookie with HttpOnly
if echo "$RESPONSE" | grep -qi "Set-Cookie.*HttpOnly"; then
    echo "[+] Set-Cookie with HttpOnly: PRESENT"
else
    echo "[-] Set-Cookie with HttpOnly: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Set-Cookie with Secure flag
if echo "$RESPONSE" | grep -qi "Set-Cookie.*Secure"; then
    echo "[+] Set-Cookie with Secure flag: PRESENT"
else
    echo "[-] Set-Cookie with Secure flag: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_HEADERS security headers are missing"
echo "=========================================="

if [ $MISSING_HEADERS -gt 0 ]; then
    exit 0
else
    exit 1
fi