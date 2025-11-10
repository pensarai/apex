#!/bin/bash

# POC: Session Cookie Missing Secure and SameSite Attributes
# This POC demonstrates that the session cookie lacks Secure and SameSite attributes

echo "=========================================="
echo "POC: Session Cookie Security Attributes"
echo "=========================================="
echo ""

TARGET="http://localhost:8082"

echo "[*] Testing authentication endpoint to capture Set-Cookie header..."
echo "[*] Target: $TARGET/password/test"
echo ""

# Perform authentication and capture the Set-Cookie header
RESPONSE=$(curl -s -v -X POST -d "password=test" "$TARGET/password/test" 2>&1)

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie:" | grep "session=")

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No session cookie found in response"
    exit 1
fi

echo "[+] Session cookie found:"
echo "$SET_COOKIE"
echo ""

# Check for Secure attribute
echo "[*] Checking for Secure attribute..."
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[+] Secure attribute: PRESENT"
    SECURE_MISSING=0
else
    echo "[-] Secure attribute: MISSING (cookie can be sent over HTTP)"
    SECURE_MISSING=1
fi
echo ""

# Check for SameSite attribute
echo "[*] Checking for SameSite attribute..."
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$SET_COOKIE" | grep -oiE "SameSite=[^;]+" | cut -d'=' -f2)
    echo "[+] SameSite attribute: PRESENT (value: $SAMESITE_VALUE)"
    SAMESITE_MISSING=0
else
    echo "[-] SameSite attribute: MISSING (vulnerable to CSRF attacks)"
    SAMESITE_MISSING=1
fi
echo ""

# Check for HttpOnly (should be present, just for completeness)
echo "[*] Checking for HttpOnly attribute (for reference)..."
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly attribute: PRESENT (good - prevents XSS cookie theft)"
else
    echo "[-] HttpOnly attribute: MISSING"
fi
echo ""

echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="

if [ $SECURE_MISSING -eq 1 ] || [ $SAMESITE_MISSING -eq 1 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo ""
    
    if [ $SECURE_MISSING -eq 1 ]; then
        echo "    - Missing Secure flag:"
        echo "      → Cookie can be transmitted over unencrypted HTTP"
        echo "      → Susceptible to man-in-the-middle attacks"
        echo "      → Session hijacking risk if accessed via HTTP"
        echo ""
    fi
    
    if [ $SAMESITE_MISSING -eq 1 ]; then
        echo "    - Missing SameSite attribute:"
        echo "      → Vulnerable to Cross-Site Request Forgery (CSRF)"
        echo "      → Cookie will be sent with cross-site requests"
        echo "      → Attackers can perform actions on behalf of users"
        echo ""
    fi
    
    echo "[!] IMPACT: Session cookies lack critical security attributes"
    exit 0
else
    echo "[+] All security attributes are properly configured"
    exit 1
fi