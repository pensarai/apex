#!/bin/bash

# POC: Missing Secure and SameSite Flags on Session Cookie
# This script demonstrates that the session cookie lacks the Secure and SameSite flags
# making it vulnerable to MITM attacks and CSRF attacks

TARGET="${1:-http://localhost:8000/}"

echo "[*] Testing for missing Secure and SameSite flags on session cookie"
echo "[*] Target: $TARGET"
echo ""

# Make HTTP request and capture Set-Cookie headers
echo "[*] Making HTTP request to capture Set-Cookie headers..."
RESPONSE=$(curl -i "$TARGET" 2>&1)

# Extract Set-Cookie header for session cookie
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i 'set-cookie: session' | head -1)

if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] No session cookie found in response"
    exit 1
fi

echo "[+] Session cookie found:"
echo "    $SESSION_COOKIE"
echo ""

# Check for Secure flag
if echo "$SESSION_COOKIE" | grep -qi "Secure"; then
    echo "[+] Secure flag: PRESENT"
    SECURE_FLAG=1
else
    echo "[-] Secure flag: MISSING (VULNERABILITY)"
    SECURE_FLAG=0
fi

# Check for SameSite attribute
if echo "$SESSION_COOKIE" | grep -qi "SameSite"; then
    echo "[+] SameSite attribute: PRESENT"
    SAMESITE_FLAG=1
else
    echo "[-] SameSite attribute: MISSING (VULNERABILITY)"
    SAMESITE_FLAG=0
fi

# Check for HttpOnly flag
if echo "$SESSION_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT"
    HTTPONLY_FLAG=1
else
    echo "[-] HttpOnly flag: MISSING"
    HTTPONLY_FLAG=0
fi

# Check for Path
if echo "$SESSION_COOKIE" | grep -qi "Path"; then
    echo "[+] Path attribute: PRESENT"
else
    echo "[-] Path attribute: MISSING"
fi

echo ""

# Determine vulnerability status
if [ $SECURE_FLAG -eq 0 ] || [ $SAMESITE_FLAG -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    if [ $SECURE_FLAG -eq 0 ]; then
        echo "    - Session cookie can be transmitted over unencrypted HTTP connections"
        echo "    - Vulnerable to Man-in-the-Middle (MITM) attacks"
    fi
    if [ $SAMESITE_FLAG -eq 0 ]; then
        echo "    - Session cookie lacks CSRF protection via SameSite attribute"
        echo "    - Vulnerable to Cross-Site Request Forgery (CSRF) attacks"
    fi
    echo ""
    echo "[*] Recommended remediation:"
    echo "    Set-Cookie: session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax"
    exit 0
else
    echo "[+] Session cookie has proper security flags"
    exit 1
fi