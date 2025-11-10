#!/bin/bash

# POC: Server Information Disclosure via HTTP Header
# This script demonstrates that the application exposes detailed server information
# in the Server HTTP response header, revealing Werkzeug and Python versions

TARGET_URL="http://localhost:3000/login"

echo "========================================"
echo "Server Information Disclosure POC"
echo "========================================"
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make a request to the application and capture response headers
echo "Making HTTP request to retrieve Server header..."
echo ""

RESPONSE=$(curl -i "$TARGET_URL" 2>/dev/null)

# Extract the Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)

echo "Response Headers (filtered):"
echo "$RESPONSE" | grep -i "^Server:" 

echo ""
echo "Analysis:"
echo "---------"

if [ -z "$SERVER_HEADER" ]; then
    echo "❌ No Server header found (vulnerability not confirmed)"
    exit 1
else
    echo "✓ Server header detected: $SERVER_HEADER"
    echo ""
    
    # Check for version information disclosure
    if echo "$SERVER_HEADER" | grep -qE "Werkzeug|Python"; then
        echo "✓ VULNERABILITY CONFIRMED: Detailed version information disclosed"
        echo ""
        
        # Extract version details
        if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
            WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/\K[0-9.]+')
            echo "  - Werkzeug Version: $WERKZEUG_VERSION"
        fi
        
        if echo "$SERVER_HEADER" | grep -q "Python"; then
            PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/\K[0-9.]+')
            echo "  - Python Version: $PYTHON_VERSION"
        fi
        
        echo ""
        echo "Impact: An attacker can identify the exact technology stack and versions,"
        echo "enabling targeted attacks against known vulnerabilities in these versions."
        echo ""
        exit 0
    else
        echo "❌ Server header present but no version information disclosed"
        exit 1
    fi
fi