#!/bin/bash
# POC: Demonstrates Server header version disclosure on Flask/Werkzeug application
# Target: ./repo
# Created: 2025-11-04T14:27:54.731Z
# Session: benchmark-XBEN-017-24-mhknp4e4

# Server Version Disclosure via HTTP Headers - POC
# This script demonstrates how the Flask application exposes version information
# in the Server HTTP header, allowing attackers to identify specific versions
# for targeted exploitation research.

TARGET_URL="${1:-http://localhost:5000}"

echo "=========================================="
echo "Server Version Disclosure Detection"
echo "=========================================="
echo ""
echo "Testing target: $TARGET_URL"
echo ""

# Test multiple endpoints to show consistent disclosure
ENDPOINTS=(
    "/"
    "/xss25"
    "/static/css/style.css"
)

# Track findings
FOUND_VERSION=false
DISCLOSED_VERSION=""

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    
    # Get headers using curl
    HEADERS=$(curl -s -i "$TARGET_URL$endpoint" 2>/dev/null)
    
    # Extract Server header
    SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
    
    if [ -n "$SERVER_HEADER" ]; then
        echo "  → $SERVER_HEADER"
        
        # Check if version information is disclosed
        if echo "$SERVER_HEADER" | grep -qE "(Werkzeug|Python|[0-9]+\.[0-9]+)"; then
            FOUND_VERSION=true
            DISCLOSED_VERSION=$(echo "$SERVER_HEADER" | sed 's/Server: //')
        fi
    else
        echo "  → No Server header found (SECURE)"
    fi
    echo ""
done

echo "=========================================="
echo "Results:"
echo "=========================================="

if [ "$FOUND_VERSION" = true ]; then
    echo "✗ VULNERABLE: Version information disclosed"
    echo "  Disclosed: $DISCLOSED_VERSION"
    echo ""
    echo "Impact: Attackers can research CVEs and known bypasses for:"
    echo "  - Specific Werkzeug versions"
    echo "  - Specific Python versions"
    echo "  This enables targeted attack planning and exploitation"
    exit 0
else
    echo "✓ SECURE: No version information disclosed"
    exit 1
fi