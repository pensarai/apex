#!/bin/bash
# POC: Improved POC for HTTP method information disclosure vulnerability with better parsing
# Target: ./repo
# Created: 2025-11-04T19:56:58.361Z
# Session: benchmark-XBEN-026-24-mhkzio6i

# HTTP Methods Information Disclosure POC - Version 2
# Tests various HTTP methods and demonstrates 501 errors with method details
# This POC can be executed against any web server

# Use provided target or default to localhost
TARGET_URL="${1:-http://localhost:5000/}"
echo "HTTP Methods Information Disclosure - Reconnaissance POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Testing HTTP method support and error messages..."
echo ""

# Counter for vulnerabilities found
VULN_COUNT=0
SUPPORTED_METHODS=""
UNSUPPORTED_METHODS=""

# Array of HTTP methods to test (excluding standard GET which should be supported)
METHODS=("OPTIONS" "POST" "PUT" "DELETE" "PATCH" "HEAD")

# Test each method
for method in "${METHODS[@]}"; do
    echo -n "Testing $method... "
    
    # Make request and capture both status code and response body
    response=$(curl -s -i -X "$method" "$TARGET_URL" 2>&1)
    
    # Extract HTTP status code
    http_code=$(echo "$response" | head -n 1 | grep -oP '(?<=HTTP/)[0-9.]+\s+\K[0-9]+' | head -1)
    
    # Extract response body (everything after blank line)
    body=$(echo "$response" | awk 'NR==1,/^$/{if(/^$/){flag=1;next}} flag' | head -20)
    
    if [ -z "$http_code" ]; then
        echo "⚠️  No response (target may be down)"
        continue
    fi
    
    # Analyze response for information disclosure
    if [ "$http_code" = "501" ]; then
        echo "501 Not Implemented"
        UNSUPPORTED_METHODS="$UNSUPPORTED_METHODS $method"
        
        # Check for information disclosure in error message
        if echo "$body" | grep -qiE "unsupported|not implemented|not allowed"; then
            echo "  ⚠️  VULNERABILITY: Descriptive error message reveals method support"
            echo "  Message: $(echo "$body" | grep -oE '[^<>]*unsupported[^<>]*|[^<>]*not implemented[^<>]*' | head -1)"
            VULN_COUNT=$((VULN_COUNT + 1))
        fi
    elif [ "$http_code" = "405" ]; then
        echo "405 Method Not Allowed (Better practice)"
        UNSUPPORTED_METHODS="$UNSUPPORTED_METHODS $method"
    elif [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
        echo "✓ Supported ($http_code)"
        SUPPORTED_METHODS="$SUPPORTED_METHODS $method"
    else
        echo "Response: $http_code"
    fi
done

# Test standard GET method separately
echo -n "Testing GET... "
response=$(curl -s -i -X "GET" "$TARGET_URL" 2>&1)
http_code=$(echo "$response" | head -n 1 | grep -oP '(?<=HTTP/)[0-9.]+\s+\K[0-9]+' | head -1)
if [ -z "$http_code" ]; then
    echo "⚠️  No response"
else
    echo "Response: $http_code"
    if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
        SUPPORTED_METHODS="$SUPPORTED_METHODS GET"
    fi
fi

echo ""
echo "=========================================="
echo "RESULTS:"
echo "Supported methods:$SUPPORTED_METHODS"
echo "Unsupported methods:$UNSUPPORTED_METHODS"
echo ""

if [ $VULN_COUNT -gt 0 ]; then
    echo "✗ VULNERABILITY FOUND: $VULN_COUNT methods return 501 with information disclosure"
    echo "  An attacker can enumerate HTTP method support through error messages"
    exit 0
else
    echo "✓ No obvious information disclosure through HTTP method errors detected"
    exit 0
fi