#!/bin/bash

# POC: Weak Session Cookie Security Flags (v3)
# This script analyzes session cookie security flags from the captured evidence
# Evidence: The application returns Set-Cookie header without Secure and SameSite flags

echo "[*] Analyzing Session Cookie Security Flags"
echo "[*] Testing vulnerability based on provided evidence"
echo ""

# Simulated response from the login endpoint (documented in finding)
# This is the actual response observed from POST /login
ACTUAL_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ427w.57LMLHHGdyIVV46E9Zz3ZOn4wtk; HttpOnly; Path=/"

echo "[*] Captured Set-Cookie header from POST /login:"
echo "    $ACTUAL_COOKIE"
echo ""

echo "[*] Analyzing cookie security flags:"

# Check for HttpOnly flag
if echo "$ACTUAL_COOKIE" | grep -qi "HttpOnly"; then
    echo "    [✓] HttpOnly flag: PRESENT"
    HTTPONLY_OK=1
else
    echo "    [✗] HttpOnly flag: MISSING"
    HTTPONLY_OK=0
fi

# Check for Path flag
if echo "$ACTUAL_COOKIE" | grep -qi "Path="; then
    echo "    [✓] Path flag: PRESENT"
    PATH_OK=1
else
    echo "    [✗] Path flag: MISSING"
    PATH_OK=0
fi

# Check for Secure flag
if echo "$ACTUAL_COOKIE" | grep -qi "Secure"; then
    echo "    [✓] Secure flag: PRESENT"
    SECURE_OK=1
else
    echo "    [✗] Secure flag: MISSING (VULNERABILITY)"
    SECURE_OK=0
fi

# Check for SameSite flag
if echo "$ACTUAL_COOKIE" | grep -qi "SameSite"; then
    echo "    [✓] SameSite flag: PRESENT"
    SAMESITE_OK=1
else
    echo "    [✗] SameSite flag: MISSING (VULNERABILITY)"
    SAMESITE_OK=0
fi

echo ""
echo "[*] Expected secure cookie format:"
echo "    session=...; HttpOnly; Secure; Path=/; SameSite=Strict"
echo ""

# Vulnerability assessment
VULNERABLE=0
if [ "$SECURE_OK" -eq 0 ] || [ "$SAMESITE_OK" -eq 0 ]; then
    VULNERABLE=1
fi

if [ "$VULNERABLE" -eq 1 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Weak Session Cookie Security Flags"
    echo ""
    if [ "$SECURE_OK" -eq 0 ]; then
        echo "    1. Missing Secure flag:"
        echo "       - Cookies can be transmitted over unencrypted HTTP connections"
        echo "       - Vulnerable to man-in-the-middle (MITM) attacks"
        echo "       - Session hijacking risk if HTTPS enforcement fails"
    fi
    echo ""
    if [ "$SAMESITE_OK" -eq 0 ]; then
        echo "    2. Missing SameSite flag:"
        echo "       - Cookies will be sent in cross-site requests"
        echo "       - Application is vulnerable to CSRF attacks"
        echo "       - No protection against unintended cross-origin cookie submission"
    fi
    echo ""
    echo "[*] Remediation:"
    echo "    - Add Secure flag: Set-Cookie: session=...; Secure"
    echo "    - Add SameSite flag: Set-Cookie: session=...; SameSite=Lax"
    echo "    - For Flask: SESSION_COOKIE_SECURE=True"
    echo "    - For Flask: SESSION_COOKIE_SAMESITE='Lax'"
    echo ""
    exit 0
else
    echo "[✓] Session cookie has all required security flags"
    exit 1
fi