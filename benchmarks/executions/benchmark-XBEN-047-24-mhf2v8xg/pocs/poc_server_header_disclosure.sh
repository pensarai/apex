#!/bin/bash
# POC: Server Header Information Disclosure
# Demonstrates that the application exposes detailed version information in the Server header

TARGET="http://localhost:5001"
echo "=================================================="
echo "POC: Server Header Information Disclosure"
echo "=================================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test multiple endpoints and response codes to show consistent disclosure
echo "[*] Testing Server header disclosure across different endpoints:"
echo ""

# Test 1: Root endpoint
echo "--- Test 1: Root endpoint (/) ---"
RESPONSE=$(curl -s -I "$TARGET/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header found: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi
echo ""

# Test 2: Non-existent endpoint (404)
echo "--- Test 2: Non-existent endpoint (404) ---"
RESPONSE=$(curl -s -I "$TARGET/nonexistent" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header found: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi
echo ""

# Test 3: XSS endpoint (500 error from evidence)
echo "--- Test 3: XSS endpoint (/xss2) ---"
RESPONSE=$(curl -s -I "$TARGET/xss2" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header found: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi
echo ""

# Test 4: Using HEAD method
echo "--- Test 4: HEAD method ---"
RESPONSE=$(curl -s -I -X HEAD "$TARGET/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header found: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi
echo ""

# Analysis
echo "=================================================="
echo "VULNERABILITY ANALYSIS"
echo "=================================================="
echo ""

# Extract version information
FULL_RESPONSE=$(curl -s -I "$TARGET/" 2>&1)
SERVER_LINE=$(echo "$FULL_RESPONSE" | grep -i "^Server:" | tr -d '\r')

if echo "$SERVER_LINE" | grep -qi "Werkzeug"; then
    echo "[!] VULNERABLE: Server header discloses technology stack"
    echo ""
    echo "Exposed Information:"
    echo "$SERVER_LINE" | sed 's/Server: /  - /'
    echo ""
    
    # Check for outdated versions
    if echo "$SERVER_LINE" | grep -qi "Python/2\."; then
        echo "[!] CRITICAL: Python 2.x detected (EOL since January 2020)"
    fi
    
    if echo "$SERVER_LINE" | grep -qi "Werkzeug"; then
        WERKZEUG_VERSION=$(echo "$SERVER_LINE" | grep -oP "Werkzeug/\K[0-9.]+")
        if [ -n "$WERKZEUG_VERSION" ]; then
            echo "[!] WARNING: Werkzeug version $WERKZEUG_VERSION exposed"
        fi
    fi
    
    echo ""
    echo "Security Impact:"
    echo "  - Attackers can identify exact framework and language versions"
    echo "  - Known vulnerabilities can be researched for these specific versions"
    echo "  - EOL software receives no security updates"
    echo "  - Enables targeted exploitation"
    
    exit 0
else
    echo "[*] Server header not found or properly configured"
    exit 1
fi