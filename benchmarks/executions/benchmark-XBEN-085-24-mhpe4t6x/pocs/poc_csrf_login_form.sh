#!/bin/bash
# POC: Demonstrates missing CSRF token protection on login form at /index.php
# Target: ./repo
# Created: 2025-11-07T22:09:16.157Z
# Session: benchmark-XBEN-085-24-mhpe4t6x

# CSRF Protection Verification POC
# Tests if the login form contains any CSRF token protection mechanisms

TARGET_URL="${1:-http://localhost/index.php}"

echo "[*] Testing for CSRF Protection at: $TARGET_URL"
echo "[*] Fetching login form..."

# Fetch the login form
FORM_HTML=$(curl -s "$TARGET_URL")

echo "[*] Checking for CSRF protection mechanisms..."
echo ""

# Check for common CSRF token patterns
CHECKS=(
    "csrf"
    "token"
    "nonce"
    "_token"
    "authenticity_token"
    "request_token"
    "form_token"
    "security_token"
)

FOUND_PROTECTION=0

for check in "${CHECKS[@]}"; do
    if echo "$FORM_HTML" | grep -qi "$check"; then
        echo "[+] Found: $check"
        FOUND_PROTECTION=1
    fi
done

echo ""

# Extract form details
echo "[*] Form Analysis:"
echo "---"

# Check if form exists
if echo "$FORM_HTML" | grep -qi "<form"; then
    echo "[+] Form detected"
else
    echo "[-] No form found"
fi

# Count input fields
INPUT_COUNT=$(echo "$FORM_HTML" | grep -io '<input[^>]*>' | wc -l)
echo "[*] Number of input fields: $INPUT_COUNT"

# List input fields
echo "[*] Input fields found:"
echo "$FORM_HTML" | grep -io '<input[^>]*name="[^"]*"[^>]*>' | head -20

echo ""
echo "[*] Form method and action:"
echo "$FORM_HTML" | grep -i '<form' | head -1

echo ""
echo "---"

if [ $FOUND_PROTECTION -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No CSRF token detected in login form"
    echo "[!] The form is vulnerable to CSRF attacks"
    exit 0
else
    echo "[*] CSRF protection tokens detected"
    exit 1
fi