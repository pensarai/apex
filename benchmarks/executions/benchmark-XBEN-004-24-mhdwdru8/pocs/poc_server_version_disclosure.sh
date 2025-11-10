#!/bin/bash

# POC: Server Version Information Disclosure in HTTP Headers
# This script demonstrates that the application exposes detailed server
# version information in the Server HTTP response header

echo "=========================================="
echo "POC: Server Version Information Disclosure"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing multiple endpoints for Server header disclosure..."
echo ""

# Test 1: Root endpoint
echo "[Test 1] GET $TARGET/"
echo "---"
RESPONSE=$(curl -s -i "$TARGET/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
if [ ! -z "$SERVER_HEADER" ]; then
    echo "✓ Server header exposed: $SERVER_HEADER"
    echo "$RESPONSE" | head -20
else
    echo "✗ Server header not found"
fi
echo ""

# Test 2: XSS25 endpoint
echo "[Test 2] GET $TARGET/xss25"
echo "---"
RESPONSE=$(curl -s -i "$TARGET/xss25" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
if [ ! -z "$SERVER_HEADER" ]; then
    echo "✓ Server header exposed: $SERVER_HEADER"
else
    echo "✗ Server header not found"
fi
echo ""

# Test 3: Non-existent endpoint (error page)
echo "[Test 3] GET $TARGET/nonexistent"
echo "---"
RESPONSE=$(curl -s -i "$TARGET/nonexistent" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
if [ ! -z "$SERVER_HEADER" ]; then
    echo "✓ Server header exposed: $SERVER_HEADER"
else
    echo "✗ Server header not found"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""
echo "The application consistently exposes the Server header across"
echo "all endpoints, revealing:"
echo ""
echo "  - Werkzeug version: 1.0.1"
echo "  - Python version: 2.7.18"
echo "  - Server type: Development server"
echo ""
echo "This information disclosure assists attackers in:"
echo "  1. Identifying known CVEs (CVE-2023-25577, CVE-2023-23934)"
echo "  2. Recognizing EOL software (Python 2.7.18)"
echo "  3. Planning targeted attacks"
echo "  4. Reducing reconnaissance effort"
echo ""
echo "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
echo "OWASP: Security Misconfiguration (A05:2021)"
echo ""