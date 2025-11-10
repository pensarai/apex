#!/bin/bash

# POC: Missing Secure Flag on CSRF Token Cookie
# This script demonstrates that the CSRF token cookie lacks the Secure flag
# and can be transmitted over unencrypted HTTP connections

TARGET_URL="${1:-http://localhost/accounts/login/}"
OUTPUT_FILE="/tmp/csrf_token_response.txt"

echo "=========================================="
echo "POC: Missing Secure Flag on CSRF Token"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Testing for CSRF token cookie security flags..."
echo ""

# Make request to login endpoint and capture response headers
echo "[*] Making HTTP request to login endpoint..."
curl -s -i "$TARGET_URL" > "$OUTPUT_FILE" 2>&1

# Extract Set-Cookie headers related to CSRF token
echo "[*] Analyzing Set-Cookie headers..."
echo ""

CSRF_COOKIE=$(grep -i "Set-Cookie.*csrftoken" "$OUTPUT_FILE")

if [ -z "$CSRF_COOKIE" ]; then
    echo "[-] No CSRF token cookie found in response"
    exit 1
fi

echo "[+] CSRF Token Cookie Found:"
echo "    $CSRF_COOKIE"
echo ""

# Check for Secure flag
if echo "$CSRF_COOKIE" | grep -qi "Secure"; then
    echo "[+] Secure flag: PRESENT ✓"
    SECURE_FLAG_PRESENT=1
else
    echo "[-] Secure flag: MISSING ✗"
    SECURE_FLAG_PRESENT=0
fi

# Check for HttpOnly flag
if echo "$CSRF_COOKIE" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT ✓"
    HTTPONLY_FLAG_PRESENT=1
else
    echo "[-] HttpOnly flag: MISSING ✗"
    HTTPONLY_FLAG_PRESENT=0
fi

# Check for SameSite flag
if echo "$CSRF_COOKIE" | grep -qi "SameSite"; then
    echo "[+] SameSite flag: PRESENT ✓"
    SAMESITE_VALUE=$(echo "$CSRF_COOKIE" | grep -oiP "SameSite=\w+")
    echo "    Value: $SAMESITE_VALUE"
    SAMESITE_FLAG_PRESENT=1
else
    echo "[-] SameSite flag: MISSING ✗"
    SAMESITE_FLAG_PRESENT=0
fi

# Check for Path flag
if echo "$CSRF_COOKIE" | grep -qi "Path"; then
    echo "[+] Path flag: PRESENT ✓"
    PATH_VALUE=$(echo "$CSRF_COOKIE" | grep -oiP "Path=[^;]+")
    echo "    Value: $PATH_VALUE"
    PATH_FLAG_PRESENT=1
else
    echo "[-] Path flag: MISSING ✗"
    PATH_FLAG_PRESENT=0
fi

# Check for Max-Age
if echo "$CSRF_COOKIE" | grep -qi "Max-Age"; then
    echo "[+] Max-Age flag: PRESENT ✓"
    MAX_AGE_VALUE=$(echo "$CSRF_COOKIE" | grep -oiP "Max-Age=\d+")
    echo "    Value: $MAX_AGE_VALUE"
    MAX_AGE_FLAG_PRESENT=1
else
    echo "[-] Max-Age flag: MISSING ✗"
    MAX_AGE_FLAG_PRESENT=0
fi

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="
echo ""

if [ "$SECURE_FLAG_PRESENT" -eq 0 ]; then
    echo "[CRITICAL] Missing Secure Flag:"
    echo "  - CSRF token can be transmitted over unencrypted HTTP"
    echo "  - Vulnerable to man-in-the-middle (MITM) attacks"
    echo "  - Token can be intercepted by network-level attackers"
    echo "  - Violates OWASP security guidelines"
    echo ""
    VULNERABILITY_FOUND=1
else
    echo "[OK] Secure flag is properly set"
    VULNERABILITY_FOUND=0
fi

if [ "$HTTPONLY_FLAG_PRESENT" -eq 0 ]; then
    echo "[WARNING] Missing HttpOnly Flag:"
    echo "  - CSRF token accessible to JavaScript"
    echo "  - Vulnerable to XSS token theft"
    echo ""
fi

echo "=========================================="
echo "RECOMMENDATION"
echo "=========================================="
echo ""
echo "Set the following in Django settings (production):"
echo "  CSRF_COOKIE_SECURE = True      # Force HTTPS transmission"
echo "  CSRF_COOKIE_HTTPONLY = True    # Prevent JavaScript access"
echo "  CSRF_COOKIE_SAMESITE = 'Strict' # Strict CSRF protection"
echo ""
echo "For development (conditional):"
echo "  CSRF_COOKIE_SECURE = not DEBUG"
echo ""

# Exit with status based on vulnerability
if [ "$VULNERABILITY_FOUND" -eq 1 ]; then
    exit 0  # POC confirms vulnerability
else
    exit 1  # Vulnerability not found
fi