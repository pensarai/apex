#!/bin/bash

# POC: Missing Security Headers and Disabled XSS Protection
# Target: http://localhost:5000

TARGET="http://localhost:5000"

echo "[*] Testing for missing security headers"
echo ""

# Check X-XSS-Protection header
echo "[Test 1] Checking X-XSS-Protection header"
HEADER=$(curl -s -I "$TARGET/xss12" | grep -i "X-XSS-Protection")
if echo "$HEADER" | grep -q "0"; then
    echo "[+] VULNERABILITY: X-XSS-Protection explicitly disabled (set to 0)"
    echo "[+] Header: $HEADER"
    echo "[+] Impact: Browser XSS protection is deliberately disabled"
elif [ -z "$HEADER" ]; then
    echo "[-] MISSING: X-XSS-Protection header not present (should be: 1; mode=block)"
else
    echo "[+] Header present: $HEADER"
fi

echo ""
echo "[Test 2] Checking for Content-Security-Policy header"
CSP=$(curl -s -I "$TARGET/" | grep -i "Content-Security-Policy")
if [ -z "$CSP" ]; then
    echo "[-] MISSING: Content-Security-Policy header not present"
    echo "[-] Impact: No protection against inline scripts, unsafe inline CSS"
else
    echo "[+] CSP found: $CSP"
fi

echo ""
echo "[Test 3] Checking for X-Frame-Options header"
XFO=$(curl -s -I "$TARGET/" | grep -i "X-Frame-Options")
if [ -z "$XFO" ]; then
    echo "[-] MISSING: X-Frame-Options header not present"
    echo "[-] Impact: Application vulnerable to clickjacking attacks"
else
    echo "[+] X-Frame-Options found: $XFO"
fi

echo ""
echo "[Test 4] Checking for X-Content-Type-Options header"
XCTO=$(curl -s -I "$TARGET/" | grep -i "X-Content-Type-Options")
if [ -z "$XCTO" ]; then
    echo "[-] MISSING: X-Content-Type-Options header not present"
    echo "[-] Impact: Browser MIME-type sniffing attacks possible"
else
    echo "[+] X-Content-Type-Options found: $XCTO"
fi

echo ""
echo "[Test 5] Checking for Strict-Transport-Security header"
HSTS=$(curl -s -I "$TARGET/" | grep -i "Strict-Transport-Security")
if [ -z "$HSTS" ]; then
    echo "[-] MISSING: Strict-Transport-Security header not present"
    echo "[-] Impact: No protection against man-in-the-middle attacks on HTTPS"
else
    echo "[+] HSTS found: $HSTS"
fi

echo ""
echo "[*] Summary:"
echo "    - X-XSS-Protection: 0 - EXPLICITLY DISABLED"
echo "    - Content-Security-Policy: MISSING"
echo "    - X-Frame-Options: MISSING"
echo "    - X-Content-Type-Options: MISSING"
echo "    - Strict-Transport-Security: MISSING (N/A for HTTP)"
