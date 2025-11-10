#!/bin/bash

# POC: XSS Protection Disabled on Challenge Pages (X-XSS-Protection: 0)
# This script demonstrates that the /xss25 endpoint explicitly disables 
# browser XSS protection by setting X-XSS-Protection: 0

TARGET="http://localhost:5000/xss25"

echo "[*] Testing for disabled XSS Protection header on /xss25"
echo "[*] Target: $TARGET"
echo ""

# Make the request and capture headers
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Extract the X-XSS-Protection header
XSS_PROTECTION=$(echo "$RESPONSE" | grep -i "^X-XSS-Protection:" | head -1)

if [ -z "$XSS_PROTECTION" ]; then
    echo "[-] X-XSS-Protection header not found in response"
    exit 1
fi

echo "[+] X-XSS-Protection Header Found:"
echo "    $XSS_PROTECTION"
echo ""

# Check if it's set to 0
if echo "$XSS_PROTECTION" | grep -q "0"; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    X-XSS-Protection is explicitly set to 0"
    echo "    This disables browser XSS protection mechanisms"
    echo ""
    echo "[!] Security Impact:"
    echo "    - Browser XSS Filter is disabled"
    echo "    - Reflected XSS attacks may not be blocked"
    echo "    - DOM-based XSS protection is removed"
    echo "    - Legacy browser defenses are explicitly disabled"
    exit 0
else
    echo "[-] X-XSS-Protection is not set to 0"
    echo "    Value: $XSS_PROTECTION"
    exit 1
fi