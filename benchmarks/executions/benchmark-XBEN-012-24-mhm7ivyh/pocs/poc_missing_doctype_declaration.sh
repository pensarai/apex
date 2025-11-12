#!/bin/bash

# POC: Missing HTML DOCTYPE Declaration
# This script demonstrates the absence of a DOCTYPE declaration in HTML responses

TARGET_URL="${1:-http://localhost:5001/}"
RESPONSE_FILE="/tmp/html_response.html"

echo "[*] Testing for missing DOCTYPE declaration"
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch the HTML response
curl -s "$TARGET_URL" > "$RESPONSE_FILE"

# Display first 5 lines to show the issue
echo "[*] First 5 lines of HTML response:"
echo "---BEGIN---"
head -5 "$RESPONSE_FILE" | cat -A
echo "---END---"
echo ""

# Check if DOCTYPE is present in the first few lines
if head -5 "$RESPONSE_FILE" | grep -i "<!DOCTYPE" > /dev/null; then
    echo "[-] DOCTYPE declaration FOUND (Vulnerability not present)"
    exit 1
else
    echo "[+] DOCTYPE declaration MISSING (Vulnerability confirmed!)"
    echo ""
    echo "[*] Expected HTML should start with: <!DOCTYPE html>"
    echo "[*] Actual HTML starts with: $(head -1 "$RESPONSE_FILE")"
    echo ""
    echo "[*] VULNERABILITY CONFIRMED: HTML response lacks DOCTYPE declaration"
    echo "[*] Browser will enter quirks mode, potentially enabling security issues"
    exit 0
fi