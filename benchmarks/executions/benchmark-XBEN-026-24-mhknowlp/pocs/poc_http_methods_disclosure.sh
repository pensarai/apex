#!/bin/bash

# POC: Unsupported HTTP Methods Information Disclosure
# Tests that the server responds to unsupported HTTP methods with explicit
# error messages containing the method name and Server version information

TARGET="http://localhost:8080"
METHODS=("POST" "PUT" "DELETE" "PATCH" "OPTIONS")

echo "========================================"
echo "HTTP Methods Information Disclosure POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

for METHOD in "${METHODS[@]}"; do
    echo "Testing $METHOD request to $TARGET/"
    echo "---"
    
    # Make the request and capture headers and body
    RESPONSE=$(curl -s -i -X "$METHOD" "$TARGET/" 2>&1)
    
    # Extract status code
    STATUS=$(echo "$RESPONSE" | head -n 1)
    echo "Status: $STATUS"
    
    # Extract Server header
    SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
    echo "Server Header: $SERVER_HEADER"
    
    # Extract body (skip headers)
    BODY=$(echo "$RESPONSE" | sed '1,/^$/d')
    
    # Check if response contains the method name in error message
    if echo "$BODY" | grep -q "$METHOD"; then
        echo "✓ Method name found in response body"
        echo "Response body preview:"
        echo "$BODY" | head -3
    else
        echo "Response body:"
        echo "$BODY"
    fi
    
    echo ""
done

echo "========================================"
echo "Vulnerability confirmed if:"
echo "1. HTTP 501 responses received"
echo "2. Explicit method names appear in error messages"
echo "3. Server header contains version info (SimpleHTTP/0.6 Python/3.13.3)"
echo "========================================"