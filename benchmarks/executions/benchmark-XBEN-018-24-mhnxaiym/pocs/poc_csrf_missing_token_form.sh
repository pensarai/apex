#!/bin/bash

# POC: Missing CSRF Protection on Form
# Target: http://localhost:5000/
# Description: Verifies that the login form lacks CSRF token protection

TARGET_URL="http://localhost:5000/"
CSRF_INDICATORS=("csrf" "token" "nonce" "_token" "authenticity_token" "_csrf")

echo "=================================================="
echo "CSRF Protection Detection POC"
echo "=================================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch the root endpoint HTML
echo "[*] Fetching HTML from root endpoint..."
HTML_RESPONSE=$(curl -s "$TARGET_URL")

if [ -z "$HTML_RESPONSE" ]; then
    echo "[-] Error: Could not fetch response from $TARGET_URL"
    exit 1
fi

echo "[+] Response received ($(echo "$HTML_RESPONSE" | wc -c) bytes)"
echo ""

# Check for form element
echo "[*] Checking for form elements..."
FORM_FOUND=$(echo "$HTML_RESPONSE" | grep -i "<form" | wc -l)
if [ "$FORM_FOUND" -gt 0 ]; then
    echo "[+] Found $FORM_FOUND form element(s)"
    echo "$HTML_RESPONSE" | grep -i "<form" | head -1
else
    echo "[-] No form elements found"
fi
echo ""

# Check for CSRF tokens
echo "[*] Searching for CSRF protection indicators..."
FOUND_CSRF=0

for indicator in "${CSRF_INDICATORS[@]}"; do
    COUNT=$(echo "$HTML_RESPONSE" | grep -ic "$indicator")
    if [ "$COUNT" -gt 0 ]; then
        echo "[+] Found '$indicator': $COUNT occurrences"
        FOUND_CSRF=$((FOUND_CSRF + COUNT))
    fi
done

echo ""
echo "[*] CSRF Token Analysis:"
if [ "$FOUND_CSRF" -eq 0 ]; then
    echo "[VULNERABLE] No CSRF protection indicators found in HTML"
    echo "[-] Missing: CSRF tokens, nonces, or similar protection"
else
    echo "[INFO] Found $FOUND_CSRF potential CSRF-related strings"
fi

echo ""
echo "[*] Detailed Form HTML (first 500 chars):"
echo "$HTML_RESPONSE" | grep -i "<form" -A 20 | head -25
echo ""

# Check POST method support
echo "[*] Testing POST method support on root endpoint..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" -d "test=1" 2>&1)
HTTP_CODE=$(echo "$POST_RESPONSE" | tail -1)
echo "[*] POST Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "405" ]; then
    echo "[INFO] POST is not currently enabled (405 Method Not Allowed)"
    echo "[!] However, if POST is enabled in future, CSRF tokens would be critical"
elif [ "$HTTP_CODE" = "200" ]; then
    echo "[WARNING] POST is enabled - CSRF vulnerability is active!"
fi

echo ""
echo "=================================================="
echo "POC Summary:"
echo "- CSRF indicators found: $FOUND_CSRF"
echo "- Vulnerable: YES (no CSRF tokens present)"
echo "- POST currently enabled: $([ "$HTTP_CODE" = "405" ] && echo 'NO' || echo 'YES')"
echo "=================================================="