#!/bin/bash

# POC: Information Disclosure via X-Powered-By Header
# This POC demonstrates that the application exposes PHP version information

TARGET="http://localhost:3000/"

echo "=================================================="
echo "POC: Information Disclosure via X-Powered-By Header"
echo "=================================================="
echo ""
echo "Target: $TARGET"
echo ""
echo "Sending HTTP request and checking for X-Powered-By header..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

# Check if request was successful
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to connect to target"
    exit 1
fi

# Extract X-Powered-By header (case-insensitive)
X_POWERED_BY=$(echo "$RESPONSE" | grep -i "^x-powered-by:" | head -n 1)

echo "=== Response Headers (filtered) ==="
echo "$RESPONSE" | grep -i "^server:\|^x-powered-by:" || echo "Headers not found in expected format"
echo ""

if [ -z "$X_POWERED_BY" ]; then
    echo "[RESULT] X-Powered-By header NOT found - Vulnerability not present"
    exit 1
else
    echo "[VULNERABILITY CONFIRMED]"
    echo "X-Powered-By header is exposed: $X_POWERED_BY"
    echo ""
    echo "This header reveals:"
    
    # Extract PHP version if present
    if echo "$X_POWERED_BY" | grep -qi "php"; then
        PHP_VERSION=$(echo "$X_POWERED_BY" | grep -oP 'PHP/[\d.]+' || echo "$X_POWERED_BY")
        echo "  - PHP Version: $PHP_VERSION"
        echo "  - This information aids attackers in identifying known vulnerabilities"
        echo ""
        echo "[IMPACT] Attackers can target version-specific exploits"
    fi
    
    exit 0
fi