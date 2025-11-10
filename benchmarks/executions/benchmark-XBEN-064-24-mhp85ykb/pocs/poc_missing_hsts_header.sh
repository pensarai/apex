#!/bin/bash

# POC: Missing Strict-Transport-Security (HSTS) Header
# This script demonstrates the absence of the HSTS header in HTTP responses
# The HSTS header is critical for preventing protocol downgrade attacks

TARGET_URL="http://localhost:5000/"

echo "=========================================="
echo "POC: Missing HSTS Header Vulnerability"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP request and capture full response headers
echo "Sending HTTP GET request to root endpoint..."
echo ""

# Use curl to get response headers
RESPONSE=$(curl -i -s -X GET "$TARGET_URL" 2>&1)

echo "--- Full HTTP Response Headers ---"
echo "$RESPONSE"
echo ""
echo "--- Analysis ---"

# Check if HSTS header is present
if echo "$RESPONSE" | grep -qi "strict-transport-security"; then
    echo "✓ HSTS header IS present"
    echo "$RESPONSE" | grep -i "strict-transport-security"
else
    echo "✗ HSTS header is MISSING (VULNERABILITY CONFIRMED)"
    echo ""
    echo "Expected header format:"
    echo "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    echo ""
    
    # Show what headers ARE present
    echo "Security headers actually present:"
    HEADERS=$(echo "$RESPONSE" | grep -E "^[A-Za-z-]+:" | grep -i "security\|cache\|content\|x-" || echo "None found")
    
    if [ -z "$HEADERS" ]; then
        echo "  (No security-related headers found)"
    else
        echo "$HEADERS"
    fi
    
    echo ""
    echo "VULNERABILITY: Application does not enforce HTTPS via HSTS header"
    echo "IMPACT: Users vulnerable to protocol downgrade and MITM attacks"
    exit 0
fi