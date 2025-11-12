#!/bin/bash

# POC: CSRF Token Cookie Missing HttpOnly and Secure Flags
# This script demonstrates that the csrftoken cookie can be accessed by JavaScript
# due to missing HttpOnly flag, making it vulnerable to XSS-based theft

TARGET_URL="${1:-http://localhost:8081}"
LOGIN_URL="${TARGET_URL}/accounts/login/"

echo "[*] Testing CSRF Token Cookie Security Attributes"
echo "[*] Target: $LOGIN_URL"
echo ""

# Fetch the login page and extract Set-Cookie headers
echo "[*] Step 1: Retrieving CSRF token cookie from login page..."
RESPONSE=$(curl -s -i "$LOGIN_URL" 2>/dev/null)

# Extract the csrftoken cookie Set-Cookie header
CSRF_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie.*csrftoken" | head -1)

if [ -z "$CSRF_COOKIE" ]; then
    echo "[-] CSRF token cookie not found in response"
    exit 1
fi

echo "[+] Found CSRF cookie header:"
echo "    $CSRF_COOKIE"
echo ""

# Check for security flags
echo "[*] Step 2: Analyzing cookie security attributes..."
echo ""

# Check for HttpOnly flag
VULN_FOUND=0
if echo "$CSRF_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] ✓ HttpOnly flag is SET (GOOD)"
    HTTPONLY_PRESENT=1
else
    echo "[-] ✗ HttpOnly flag is MISSING (VULNERABLE)"
    echo "    → Cookie is accessible to JavaScript"
    echo "    → Vulnerable to XSS-based theft via document.cookie"
    HTTPONLY_PRESENT=0
    VULN_FOUND=1
fi

echo ""

# Check for Secure flag
if echo "$CSRF_COOKIE" | grep -qi "Secure"; then
    echo "[+] ✓ Secure flag is SET (GOOD)"
    SECURE_PRESENT=1
else
    echo "[-] ✗ Secure flag is MISSING (VULNERABLE)"
    echo "    → Cookie can be transmitted over HTTP"
    echo "    → Vulnerable to MITM attacks"
    SECURE_PRESENT=0
    VULN_FOUND=1
fi

echo ""

# Check for SameSite
if echo "$CSRF_COOKIE" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$CSRF_COOKIE" | grep -oiP 'SameSite=\K[^ ;]+' | head -1)
    echo "[+] ✓ SameSite=$SAMESITE_VALUE is SET (provides some CSRF protection)"
else
    echo "[-] ✗ SameSite flag is MISSING"
fi

echo ""
echo "[*] Step 3: Vulnerability Assessment..."
echo ""

if [ $HTTPONLY_PRESENT -eq 0 ] && [ $SECURE_PRESENT -eq 0 ]; then
    echo "[!] CRITICAL: Both HttpOnly and Secure flags are missing"
    echo "    Attack Scenario:"
    echo "    1. Attacker injects XSS payload into application"
    echo "    2. Victim visits page with malicious script"
    echo "    3. Script executes: var token = document.cookie.match(/csrftoken=([^;]+)/)[1]"
    echo "    4. CSRF token is extracted and sent to attacker"
    echo "    5. Attacker uses token to forge requests on behalf of victim"
elif [ $HTTPONLY_PRESENT -eq 0 ]; then
    echo "[!] HIGH: HttpOnly flag is missing"
    echo "    CSRF token is accessible to JavaScript via XSS attacks"
fi

if [ $SECURE_PRESENT -eq 0 ] && [ $HTTPONLY_PRESENT -eq 1 ]; then
    echo "[!] HIGH: Secure flag is missing"
    echo "    Cookie can be transmitted over unencrypted HTTP connections"
fi

echo ""
echo "[*] Step 4: Demonstration of XSS Vulnerability"
echo ""
echo "[!] JavaScript payload to extract CSRF token (would work if XSS present):"
echo "    document.cookie.match(/csrftoken=([^;]+)/)[1]"
echo ""
echo "[!] This can be executed in browser console to verify accessibility:"
echo "    1. Open Developer Tools (F12)"
echo "    2. Go to Console tab"
echo "    3. Paste the command above"
echo "    4. If CSRF token is returned, the vulnerability is confirmed"
echo ""

# Summary
echo "[*] Step 5: Summary"
echo ""

if [ $VULN_FOUND -eq 1 ]; then
    echo "[VULNERABLE] The CSRF token cookie lacks proper security attributes:"
    [ $HTTPONLY_PRESENT -eq 0 ] && echo "  ✗ Missing HttpOnly flag (JavaScript-accessible)"
    [ $SECURE_PRESENT -eq 0 ] && echo "  ✗ Missing Secure flag (can be sent over HTTP)"
    echo ""
    echo "[REMEDIATION] Django settings.py should include:"
    echo "  CSRF_COOKIE_HTTPONLY = True"
    echo "  CSRF_COOKIE_SECURE = True"
    echo ""
    echo "[CONFIRMED] Vulnerability successfully demonstrated"
    exit 0
else
    echo "[SECURE] CSRF token cookie has proper security attributes"
    exit 1
fi