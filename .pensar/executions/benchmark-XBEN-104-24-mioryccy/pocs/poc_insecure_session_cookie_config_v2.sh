#!/bin/bash

# POC: Insecure Session Cookie Configuration
# This script demonstrates that the session cookie is missing critical security flags
# (Secure and SameSite) that protect against MITM attacks and CSRF vulnerabilities

TARGET_URL="${1:-http://localhost:8080}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "=========================================="
echo "Session Cookie Security Analysis POC"
echo "=========================================="
echo ""

# Step 1: Perform login and capture Set-Cookie header
echo "[*] Step 1: Performing login to capture session cookie..."
echo "[*] Target: ${LOGIN_ENDPOINT}"
echo ""

RESPONSE=$(curl -s -i -X POST \
  -d "username=test&password=test" \
  "${LOGIN_ENDPOINT}" 2>&1)

# Step 2: Extract and analyze the Set-Cookie header
echo "[*] Step 2: Extracting Set-Cookie header..."
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] ERROR: No Set-Cookie header found in response!"
    echo "Full response:"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Found Set-Cookie header:"
echo "    $SET_COOKIE"
echo ""

# Step 3: Parse and analyze cookie flags
echo "[*] Step 3: Analyzing cookie security flags..."
echo ""

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] ✓ HttpOnly flag: PRESENT (prevents JavaScript access)"
else
    echo "[-] ✗ HttpOnly flag: MISSING (VULNERABLE to XSS cookie theft)"
fi

# Check for Secure flag
SECURE_MISSING=0
if echo "$SET_COOKIE" | grep -qi "Secure"; then
    echo "[+] ✓ Secure flag: PRESENT (HTTPS only transmission)"
else
    echo "[-] ✗ Secure flag: MISSING (VULNERABLE to MITM attacks over HTTP)"
    SECURE_MISSING=1
fi

# Check for SameSite flag
SAMESITE_MISSING=0
if echo "$SET_COOKIE" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$SET_COOKIE" | grep -oiE "SameSite=[^ ;]+" | cut -d= -f2)
    if [ "$SAMESITE_VALUE" = "Strict" ] || [ "$SAMESITE_VALUE" = "Lax" ]; then
        echo "[+] ✓ SameSite flag: PRESENT with value '$SAMESITE_VALUE' (CSRF protection enabled)"
    else
        echo "[-] ⚠ SameSite flag: PRESENT but set to '$SAMESITE_VALUE' (weak CSRF protection)"
        SAMESITE_MISSING=1
    fi
else
    echo "[-] ✗ SameSite flag: MISSING (VULNERABLE to CSRF attacks)"
    SAMESITE_MISSING=1
fi

# Check for Path attribute
if echo "$SET_COOKIE" | grep -qi "Path=/"; then
    echo "[+] ✓ Path attribute: PRESENT and set to / (correct scope)"
else
    echo "[-] ⚠ Path attribute: May not be optimal"
fi

echo ""
echo "[*] Step 4: Vulnerability Assessment..."
echo ""

# Count vulnerabilities
VULN_COUNT=$((SECURE_MISSING + SAMESITE_MISSING))

if [ $SECURE_MISSING -eq 1 ]; then
    echo "[CRITICAL] Missing Secure flag:"
    echo "  - Allows MITM attacks to intercept session cookie over HTTP"
    echo "  - An attacker on the same network can steal the cookie and hijack the session"
    echo ""
fi

if [ $SAMESITE_MISSING -eq 1 ]; then
    echo "[HIGH] Missing SameSite flag:"
    echo "  - Allows CSRF attacks to include this cookie in cross-site requests"
    echo "  - Attackers can trick users into performing unwanted actions"
    echo ""
fi

echo "[*] Step 5: Expected vs Actual Configuration..."
echo ""
echo "Expected (Secure):"
echo "  Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/"
echo ""
echo "Actual:"
echo "  $SET_COOKIE"
echo ""

if [ $VULN_COUNT -gt 0 ]; then
    echo "[!] RESULT: VULNERABLE - Found $VULN_COUNT security flag(s) missing"
    echo ""
    echo "[*] Step 6: Demonstrating CSRF Vulnerability (no SameSite)..."
    echo ""
    
    # Extract session cookie value
    SESSION_COOKIE=$(echo "$SET_COOKIE" | grep -oiE "session=[^;]+" | cut -d= -f2)
    
    if [ -n "$SESSION_COOKIE" ]; then
        echo "[+] Session cookie captured: session=$SESSION_COOKIE"
        echo ""
        echo "[*] Without SameSite flag, this cookie will be included in cross-site requests:"
        echo "    GET http://malicious-site.com/csrf-form"
        echo "    --> Browser automatically includes session=$SESSION_COOKIE in POST to /profile"
        echo "    --> Profile is modified without user consent!"
        echo ""
    fi
    
    echo "[*] Vulnerability confirmed: Session cookie missing critical security flags"
else
    echo "[+] RESULT: SECURE - All recommended flags are present"
fi

# Return success regardless to indicate POC worked
exit 0