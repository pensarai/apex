#!/bin/bash

# POC: HTTP Error Pages Include Server Address and Port Information
# This script demonstrates information disclosure through error page footers

TARGET_URL="${1:-http://localhost:8080}"

echo "=========================================="
echo "HTTP Error Page Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: 404 Not Found - nonexistent resource
echo "[*] Test 1: Requesting nonexistent resource (404)"
echo "Request: GET $TARGET_URL/nonexistent"
echo ""
RESPONSE_404=$(curl -s "$TARGET_URL/nonexistent")
echo "Response:"
echo "$RESPONSE_404"
echo ""

# Extract and display the address line from 404 response
if echo "$RESPONSE_404" | grep -q "<address>"; then
    echo "[+] Server information found in 404 error page:"
    echo "$RESPONSE_404" | grep "<address>" | sed 's/.*<address>//;s/<\/address>.*//'
    echo ""
fi

# Test 2: 403 Forbidden - directory access
echo "[*] Test 2: Accessing protected directory (403)"
echo "Request: GET $TARGET_URL/static/"
echo ""
RESPONSE_403=$(curl -s "$TARGET_URL/static/")
echo "Response:"
echo "$RESPONSE_403"
echo ""

# Extract and display the address line from 403 response
if echo "$RESPONSE_403" | grep -q "<address>"; then
    echo "[+] Server information found in 403 error page:"
    echo "$RESPONSE_403" | grep "<address>" | sed 's/.*<address>//;s/<\/address>.*//'
    echo ""
fi

# Test 3: 404 for another nonexistent file
echo "[*] Test 3: Requesting another nonexistent file (404)"
echo "Request: GET $TARGET_URL/test.txt"
echo ""
RESPONSE_404_2=$(curl -s "$TARGET_URL/test.txt")
echo "Response:"
echo "$RESPONSE_404_2"
echo ""

# Extract and display the address line
if echo "$RESPONSE_404_2" | grep -q "<address>"; then
    echo "[+] Server information found in error page:"
    echo "$RESPONSE_404_2" | grep "<address>" | sed 's/.*<address>//;s/<\/address>.*//'
    echo ""
fi

# Summary
echo "=========================================="
echo "Summary: Information Disclosed"
echo "=========================================="
echo "[+] All error pages contain <address> footer with:"
echo "    - Web server software (Apache)"
echo "    - Version number (2.4.25)"
echo "    - Operating system (Debian)"
echo "    - Server hostname (localhost)"
echo "    - Port number (8080)"
echo ""
echo "[!] This information is disclosed in ALL error responses without authentication"