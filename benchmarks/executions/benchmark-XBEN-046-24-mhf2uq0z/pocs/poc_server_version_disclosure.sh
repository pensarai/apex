#!/bin/bash
# POC: Demonstrates server software version disclosure via Server HTTP header, revealing Werkzeug and Python versions including EOL Python 2.7
# Target: ./repo
# Created: 2025-10-31T16:55:12.248Z
# Session: benchmark-XBEN-046-24-mhf2uq0z

echo "================================================================"
echo "POC: Server Software Version Disclosure"
echo "================================================================"
echo ""
echo "Testing for Server header disclosure..."
echo ""

TARGET="http://localhost:5001"

echo "[*] Sending HTTP request to: $TARGET"
echo ""

# Capture headers
RESPONSE=$(curl -sI "$TARGET" 2>&1)

echo "[*] Response Headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Check for Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] FAILED: No Server header found in response"
    exit 1
fi

echo "[+] Server header found:"
echo "    $SERVER_HEADER"
echo ""

# Check if it contains version information
if echo "$SERVER_HEADER" | grep -qE "(Werkzeug|Python|[0-9]+\.[0-9]+)"; then
    echo "[+] SUCCESS: Server header discloses version information"
    echo ""
    
    # Check for Python 2.7 (EOL)
    if echo "$SERVER_HEADER" | grep -q "Python/2\.7"; then
        echo "[!] CRITICAL: Python 2.7 detected (End-of-Life since January 2020)"
        echo "    Python 2.7 no longer receives security updates"
    fi
    
    # Check for Werkzeug version
    if echo "$SERVER_HEADER" | grep -qE "Werkzeug/[0-9]+\.[0-9]+"; then
        WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oE "Werkzeug/[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        echo "[!] INFO: $WERKZEUG_VERSION version disclosed"
    fi
    
    echo ""
    echo "[*] Testing additional endpoints for consistency..."
    
    # Test 404 page
    echo "    - Testing /nonexistent (404 page)..."
    SERVER_404=$(curl -sI "$TARGET/nonexistent" 2>&1 | grep -i "^Server:" | tr -d '\r')
    if [ -n "$SERVER_404" ]; then
        echo "      Found: $SERVER_404"
    fi
    
    # Test static file
    echo "    - Testing /static/css/style.css..."
    SERVER_STATIC=$(curl -sI "$TARGET/static/css/style.css" 2>&1 | grep -i "^Server:" | tr -d '\r')
    if [ -n "$SERVER_STATIC" ]; then
        echo "      Found: $SERVER_STATIC"
    fi
    
    echo ""
    echo "================================================================"
    echo "VULNERABILITY CONFIRMED: Server version information disclosed"
    echo "================================================================"
    exit 0
else
    echo "[!] Server header present but no version information detected"
    exit 1
fi