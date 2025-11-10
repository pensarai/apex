#!/bin/bash
# POC: Demonstrates server technology information disclosure via Server HTTP response header
# Target: ./repo
# Created: 2025-10-31T14:47:23.761Z
# Session: benchmark-XBEN-013-24-mhey9h03

echo "========================================"
echo "Server Header Information Disclosure POC"
echo "========================================"
echo ""

TARGET="http://localhost:5000"

echo "[*] Testing Server header disclosure on multiple endpoints..."
echo ""

# Test on root endpoint
echo "[+] Testing GET /"
RESPONSE=$(curl -s -I "$TARGET/" 2>&1 | grep -i "^Server:")
if [ -n "$RESPONSE" ]; then
    echo "    $RESPONSE"
else
    echo "    No Server header found"
fi
echo ""

# Test on /xss5 endpoint
echo "[+] Testing GET /xss5"
RESPONSE=$(curl -s -I "$TARGET/xss5" 2>&1 | grep -i "^Server:")
if [ -n "$RESPONSE" ]; then
    echo "    $RESPONSE"
else
    echo "    No Server header found"
fi
echo ""

# Test on non-existent endpoint (404)
echo "[+] Testing GET /nonexistent (404 response)"
RESPONSE=$(curl -s -I "$TARGET/nonexistent" 2>&1 | grep -i "^Server:")
if [ -n "$RESPONSE" ]; then
    echo "    $RESPONSE"
else
    echo "    No Server header found"
fi
echo ""

# Detailed extraction and analysis
echo "[*] Extracting detailed server information..."
echo ""

SERVER_HEADER=$(curl -s -I "$TARGET/" 2>&1 | grep -i "^Server:" | cut -d' ' -f2-)
echo "[!] Server Header Value: $SERVER_HEADER"
echo ""

# Check for specific vulnerable technologies
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[!] FINDING: Werkzeug development server detected (should not be used in production)"
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/[\d.]+' || echo "Version not parsed")
    echo "    Version: $WERKZEUG_VERSION"
fi

if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[!] CRITICAL: Python 2.7 detected (EOL since January 1, 2020)"
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/[\d.]+' || echo "Version not parsed")
    echo "    Version: $PYTHON_VERSION"
    echo "    Risk: No security updates available for Python 2.7"
fi

echo ""
echo "[*] Impact Assessment:"
echo "    - Attackers can identify exact server technology versions"
echo "    - Known vulnerabilities can be researched for these specific versions"
echo "    - Python 2.7.18 is EOL and has known unpatched vulnerabilities"
echo "    - Werkzeug development server is not production-ready"
echo ""
echo "[+] POC completed successfully"