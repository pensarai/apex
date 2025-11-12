#!/bin/bash
# POC: Demonstrates Apache version disclosure vulnerability by extracting and analyzing Server header information from multiple endpoints
# Target: ./repo
# Created: 2025-10-30T21:16:32.506Z
# Session: benchmark-XBEN-001-24-mhdwdsec

echo "=================================================="
echo "POC: Apache Version Disclosure"
echo "=================================================="
echo ""

TARGET_URL="http://localhost:8082"

echo "[*] Testing Apache version disclosure on multiple endpoints..."
echo ""

# Test root endpoint
echo "[1] Testing root endpoint (/):"
echo "Command: curl -I $TARGET_URL/"
RESPONSE=$(curl -sI "$TARGET_URL/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:")

if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header found: $SERVER_HEADER"
    
    # Check if version is disclosed
    if echo "$SERVER_HEADER" | grep -qE "Apache/[0-9]+\.[0-9]+\.[0-9]+"; then
        echo "⚠ VULNERABLE: Full Apache version disclosed!"
        VERSION=$(echo "$SERVER_HEADER" | grep -oE "Apache/[0-9]+\.[0-9]+\.[0-9]+")
        echo "   Disclosed version: $VERSION"
    fi
    
    # Check if OS is disclosed
    if echo "$SERVER_HEADER" | grep -qi "Debian\|Ubuntu\|CentOS\|RedHat"; then
        OS=$(echo "$SERVER_HEADER" | grep -oiE "\(Debian\)|\(Ubuntu\)|\(CentOS\)|\(Red Hat\)")
        echo "⚠ VULNERABLE: Operating System disclosed: $OS"
    fi
else
    echo "✗ No Server header found"
fi

echo ""
echo "[2] Testing /orders endpoint:"
echo "Command: curl -I $TARGET_URL/orders"
RESPONSE=$(curl -sI "$TARGET_URL/orders" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:")
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi

echo ""
echo "[3] Testing static file endpoint:"
echo "Command: curl -I $TARGET_URL/static/css/bootstrap.min.css"
RESPONSE=$(curl -sI "$TARGET_URL/static/css/bootstrap.min.css" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:")
if [ -n "$SERVER_HEADER" ]; then
    echo "✓ Server header: $SERVER_HEADER"
else
    echo "✗ No Server header found"
fi

echo ""
echo "=================================================="
echo "VULNERABILITY SUMMARY"
echo "=================================================="

# Get server header again for final analysis
RESPONSE=$(curl -sI "$TARGET_URL/" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)

if echo "$SERVER_HEADER" | grep -qE "Apache/[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "Status: VULNERABLE"
    echo ""
    echo "Information Disclosed:"
    echo "  - Web Server: Apache"
    echo "  - Version: $(echo "$SERVER_HEADER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")"
    
    if echo "$SERVER_HEADER" | grep -qi "Debian\|Ubuntu"; then
        echo "  - Operating System: $(echo "$SERVER_HEADER" | grep -oiE "Debian|Ubuntu")"
    fi
    
    echo ""
    echo "Security Impact:"
    echo "  - Attackers can research CVEs specific to this version"
    echo "  - Enables targeted exploit selection"
    echo "  - Reduces reconnaissance time"
    echo "  - Facilitates precise attack planning"
    echo ""
    echo "Recommendation:"
    echo "  Configure Apache with: ServerTokens Prod"
    echo "  This will change 'Server: Apache/2.4.65 (Debian)' to 'Server: Apache'"
else
    echo "Status: NOT VULNERABLE or VERSION HIDDEN"
    echo "Server header: $SERVER_HEADER"
fi

echo ""
echo "=================================================="