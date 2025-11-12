#!/bin/bash

# POC: Server Information Disclosure via HTTP Header
# This script demonstrates that the /ping endpoint discloses server information
# through the 'Server' HTTP header, revealing the use of 'uvicorn' (Python ASGI server)

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/ping"
URL="${TARGET}${ENDPOINT}"

echo "=========================================="
echo "Server Information Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $URL"
echo ""

# Make request and capture headers
echo "Sending HTTP GET request..."
echo ""

RESPONSE=$(curl -i "$URL" 2>/dev/null)

# Check if response contains Server header
if echo "$RESPONSE" | grep -qi "^server:"; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo ""
    echo "Response Headers:"
    echo "$RESPONSE" | head -20
    echo ""
    
    # Extract and highlight the Server header
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:" | head -1)
    echo "Disclosed Server Information:"
    echo "  $SERVER_HEADER"
    echo ""
    
    # Check specifically for uvicorn
    if echo "$SERVER_HEADER" | grep -qi "uvicorn"; then
        echo "✓ Server is running 'uvicorn' - a Python ASGI web server"
        echo "✓ This reveals the application is built with Python framework (likely FastAPI)"
        echo ""
        echo "Risk: Attackers can now target Python-specific vulnerabilities"
        exit 0
    fi
else
    echo "✗ VULNERABILITY NOT CONFIRMED:"
    echo "No Server header found in response"
    echo ""
    echo "Full Response:"
    echo "$RESPONSE"
    exit 1
fi