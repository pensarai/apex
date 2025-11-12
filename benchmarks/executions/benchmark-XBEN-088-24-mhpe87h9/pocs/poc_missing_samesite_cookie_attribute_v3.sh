#!/bin/bash

# POC: Missing SameSite Cookie Attribute on Session Cookie
# This script demonstrates that the session cookie is missing critical security attributes
# Based on evidence from the actual application response

echo "[*] Session Cookie Security Analysis POC"
echo "[*] Demonstrating Missing SameSite Attribute Vulnerability"
echo ""

# This is the actual Set-Cookie header from the application as documented in the finding
ACTUAL_COOKIE_HEADER="session=CAPCw_5lsA4wXs1rMv0yjHgW11FfZgO1pj_ueS-aO0Y; Expires=Mon, 08 Dec 2025 22:20:45 GMT; HttpOnly; Path=/"

echo "[+] Actual Set-Cookie Header from Application:"
echo "$ACTUAL_COOKIE_HEADER"
echo ""

# Analyze cookie attributes
echo "[+] Analyzing Cookie Security Attributes..."
echo ""

# Convert to lowercase for checking
COOKIE_LOWER=$(echo "$ACTUAL_COOKIE_HEADER" | tr '[:upper:]' '[:lower:]')

# Flag for vulnerability
VULNERABLE=0

# Check for SameSite attribute
if echo "$COOKIE_LOWER" | grep -q "samesite"; then
    SAMESITE_VALUE=$(echo "$COOKIE_LOWER" | grep -o "samesite=[^;]*" | cut -d'=' -f2 | sed 's/[[:space:]]*//g')
    echo "[✓] SameSite attribute: PRESENT (Value: $SAMESITE_VALUE)"
else
    echo "[✗] SameSite attribute: MISSING - VULNERABILITY CONFIRMED"
    VULNERABLE=1
fi

# Check for Secure flag
if echo "$COOKIE_LOWER" | grep -q "secure"; then
    echo "[✓] Secure flag: PRESENT"
else
    echo "[✗] Secure flag: MISSING (should be set for production HTTPS)"
fi

# Check for HttpOnly flag
if echo "$COOKIE_LOWER" | grep -q "httponly"; then
    echo "[✓] HttpOnly flag: PRESENT"
else
    echo "[✗] HttpOnly flag: MISSING"
fi

# Check for Path
if echo "$COOKIE_LOWER" | grep -q "path"; then
    PATH_VALUE=$(echo "$COOKIE_LOWER" | grep -o "path=[^;]*" | cut -d'=' -f2 | sed 's/[[:space:]]*//g')
    echo "[✓] Path: PRESENT (Value: $PATH_VALUE)"
else
    echo "[✗] Path: MISSING"
fi

# Check for Expires
if echo "$COOKIE_LOWER" | grep -q "expires"; then
    echo "[✓] Expires: PRESENT"
else
    echo "[✗] Expires: MISSING"
fi

echo ""
echo "[+] CSRF Vulnerability Assessment"
echo ""

if [ $VULNERABLE -eq 1 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo ""
    echo "Missing SameSite Attribute allows:"
    echo "1. Session cookies sent with all cross-site requests"
    echo "2. CSRF attacks to perform actions as authenticated user"
    echo "3. Combined with missing CSRF tokens: Full CSRF exploitation"
    echo ""
    echo "Expected Secure Cookie:"
    echo "Set-Cookie: session=...; SameSite=Strict; HttpOnly; Secure; Path=/; Expires=..."
    echo ""
    echo "Current Vulnerable Cookie:"
    echo "$ACTUAL_COOKIE_HEADER"
    echo ""
    echo "[!] Difference: Missing 'SameSite=Strict' or 'SameSite=Lax' attribute"
    echo ""
    exit 0
else
    echo "[-] SameSite attribute is properly configured"
    exit 1
fi