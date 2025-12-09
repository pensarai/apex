#!/bin/bash

# POC: Missing HttpOnly Flag on CSRF Cookie
# This script demonstrates that the CSRF token cookie lacks the HttpOnly flag,
# meaning it can be accessed by JavaScript in the browser

TARGET_URL="${1:-http://localhost:8000/accounts/login/}"
TEMP_RESPONSE=$(mktemp)

echo "[*] Testing CSRF Cookie Security on: $TARGET_URL"
echo ""

# Fetch the login page and capture Set-Cookie headers
echo "[+] Fetching login page to examine Set-Cookie headers..."
curl -s -i "$TARGET_URL" > "$TEMP_RESPONSE" 2>&1

# Extract Set-Cookie header for CSRF token
CSRF_COOKIE=$(grep -i "set-cookie.*csrftoken" "$TEMP_RESPONSE")

if [ -z "$CSRF_COOKIE" ]; then
    echo "[-] No CSRF token cookie found in response"
    rm "$TEMP_RESPONSE"
    exit 1
fi

echo "[+] Found CSRF Cookie Header:"
echo "    $CSRF_COOKIE"
echo ""

# Check for HttpOnly flag
if echo "$CSRF_COOKIE" | grep -i "HttpOnly" > /dev/null; then
    echo "[✓] HttpOnly flag is PRESENT (SECURE)"
    HTTPONLY_PRESENT=true
else
    echo "[✗] HttpOnly flag is MISSING (VULNERABLE)"
    HTTPONLY_PRESENT=false
fi

# Check for Secure flag
if echo "$CSRF_COOKIE" | grep -i "Secure" > /dev/null; then
    echo "[✓] Secure flag is PRESENT (SECURE)"
    SECURE_PRESENT=true
else
    echo "[✗] Secure flag is MISSING (VULNERABLE)"
    SECURE_PRESENT=false
fi

# Check for SameSite flag
if echo "$CSRF_COOKIE" | grep -i "SameSite" > /dev/null; then
    echo "[✓] SameSite flag is PRESENT (PARTIAL PROTECTION)"
    SAMESITE_VALUE=$(echo "$CSRF_COOKIE" | grep -oiE "SameSite=[^;]+" | cut -d'=' -f2)
    echo "    SameSite value: $SAMESITE_VALUE"
else
    echo "[✗] SameSite flag is MISSING (VULNERABLE)"
fi

echo ""
echo "[*] Security Analysis:"
echo "    - HttpOnly missing means JavaScript can access the cookie via document.cookie"
echo "    - An XSS attack could steal the CSRF token and perform CSRF attacks"
echo "    - Even with SameSite=Lax, the XSS+CSRF combination is dangerous"
echo ""

# Demonstrate how JavaScript could access the cookie (if HttpOnly is not present)
if [ "$HTTPONLY_PRESENT" = false ]; then
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "    The CSRF token cookie CAN be accessed by JavaScript because HttpOnly is missing"
    echo "    Example JavaScript payload that could be injected via XSS:"
    echo "    > document.cookie  // Would expose: csrftoken=..."
    echo ""
    echo "[!] Risk: Combined with XSS, an attacker could:"
    echo "    1. Steal the CSRF token value"
    echo "    2. Use it to forge malicious requests on behalf of the victim"
    echo "    3. Escalate XSS to account takeover or other attacks"
    VULN_CONFIRMED=true
else
    echo "[-] HttpOnly flag is present - JavaScript cannot access the cookie"
    VULN_CONFIRMED=false
fi

echo ""
echo "[*] Cookie Details:"
echo "$CSRF_COOKIE" | sed 's/;/;\n    /g'

rm "$TEMP_RESPONSE"

# Exit with success if vulnerability is confirmed
if [ "$VULN_CONFIRMED" = true ]; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Missing HttpOnly flag on CSRF cookie"
    exit 0
else
    echo ""
    echo "[-] VULNERABILITY NOT FOUND: HttpOnly flag is properly set"
    exit 1
fi