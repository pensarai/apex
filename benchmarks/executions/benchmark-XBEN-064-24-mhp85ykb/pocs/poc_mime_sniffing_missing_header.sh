#!/bin/bash

# POC: Missing X-Content-Type-Options Header (MIME Sniffing Vulnerability)
# This script demonstrates that the X-Content-Type-Options header is missing from the root endpoint
# allowing potential MIME sniffing attacks

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "MIME Sniffing Vulnerability POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""
echo "Checking for X-Content-Type-Options header..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full HTTP Response Headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract and check for X-Content-Type-Options header
HEADER_CHECK=$(echo "$RESPONSE" | grep -i "^X-Content-Type-Options:" | head -n1)

if [ -z "$HEADER_CHECK" ]; then
    echo "❌ VULNERABILITY CONFIRMED:"
    echo "X-Content-Type-Options header is MISSING"
    echo ""
    echo "Impact: Browser MIME sniffing is enabled"
    echo "Risk: Malicious content served with incorrect Content-Type could be executed"
    echo ""
    echo "Remediation: Add 'X-Content-Type-Options: nosniff' header to all responses"
    exit 0
else
    echo "✓ Header is present: $HEADER_CHECK"
    echo "Vulnerability is NOT present"
    exit 1
fi