#!/bin/bash

# POC: Information Disclosure via PHP Error Messages
# Demonstrates that PHP error messages and version information are exposed

TARGET="${1:-http://localhost:80}"
RESPONSE_FILE="/tmp/php_error_response.txt"
HEADERS_FILE="/tmp/php_error_headers.txt"

echo "[*] Testing for information disclosure via PHP error messages"
echo "[*] Target: $TARGET"
echo ""

# Fetch the response with headers
echo "[*] Sending GET request to $TARGET"
curl -i "$TARGET" -o "$RESPONSE_FILE" -D "$HEADERS_FILE" 2>/dev/null

echo "[*] Checking for PHP error messages in response body..."
echo ""

# Check for PHP error messages
if grep -q "Notice" "$RESPONSE_FILE" || grep -q "Warning" "$RESPONSE_FILE" || grep -q "Error" "$RESPONSE_FILE"; then
    echo "[+] VULNERABLE: PHP error messages found in response body!"
    echo ""
    echo "=== Error Messages Found ==="
    grep -E "Notice|Warning|Error|Undefined" "$RESPONSE_FILE" | head -5
    echo ""
    
    # Check for file path disclosure
    if grep -q "/var/www/html/" "$RESPONSE_FILE"; then
        echo "[+] CONFIRMED: Full file paths are disclosed in error messages!"
        echo "=== File Path Disclosure ==="
        grep -o "/var/www/html/[^<]*" "$RESPONSE_FILE" | head -3
        echo ""
    fi
    
    # Check for line numbers
    if grep -qE "on line <b>[0-9]+</b>" "$RESPONSE_FILE"; then
        echo "[+] CONFIRMED: Line numbers are disclosed in error messages!"
        echo "=== Line Number Disclosure ==="
        grep -oE "on line <b>[0-9]+</b>" "$RESPONSE_FILE" | head -3
        echo ""
    fi
else
    echo "[-] No PHP error messages found in response body"
fi

echo "[*] Checking HTTP response headers for information disclosure..."
echo ""

# Check for X-Powered-By header
if grep -qi "X-Powered-By" "$HEADERS_FILE"; then
    echo "[+] VULNERABLE: X-Powered-By header exposes technology stack!"
    echo "=== Technology Stack Disclosure ==="
    grep -i "X-Powered-By" "$HEADERS_FILE"
    echo ""
else
    echo "[-] X-Powered-By header not found"
fi

# Check for Server header
if grep -qi "^Server:" "$HEADERS_FILE"; then
    echo "[+] Server header found:"
    echo "=== Server Information ==="
    grep -i "^Server:" "$HEADERS_FILE"
    echo ""
fi

echo "[*] Summary of information disclosed:"
echo "    - PHP error messages: YES/NO"
echo "    - File paths: YES/NO"
echo "    - Line numbers: YES/NO"
echo "    - PHP version: YES/NO"
echo ""
echo "[*] This allows attackers to:"
echo "    - Map application structure"
echo "    - Identify vulnerable code locations"
echo "    - Discover version-specific exploits"
echo "    - Understand internal logic"

# Cleanup
rm -f "$RESPONSE_FILE" "$HEADERS_FILE"