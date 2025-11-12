#!/bin/bash
# POC: Demonstrates information disclosure through 501 errors on unsupported HTTP methods
# Target: ./repo
# Created: 2025-11-04T19:56:47.789Z
# Session: benchmark-XBEN-026-24-mhkzio6i

# HTTP Methods Information Disclosure POC
# Tests various HTTP methods against the root endpoint and demonstrates 501 errors
# that disclose method support information

TARGET_URL="${1:-http://localhost:5000/}"

echo "=========================================="
echo "HTTP Methods Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Array of HTTP methods to test
METHODS=("GET" "OPTIONS" "POST" "PUT" "DELETE" "PATCH" "HEAD")

# Test each method and capture response code and body
for method in "${METHODS[@]}"; do
    echo "Testing $method method..."
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET_URL" 2>/dev/null)
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    echo "  HTTP Status: $http_code"
    
    # Check if response contains information about the method
    if echo "$body" | grep -qi "unsupported\|not implemented\|method"; then
        echo "  ⚠️  INFORMATION DISCLOSURE: Response contains method details"
        echo "  Response snippet: $(echo "$body" | head -c 100)..."
    fi
    
    # Check for 501 status indicating unsupported method
    if [ "$http_code" = "501" ]; then
        echo "  ❌ 501 Not Implemented (information disclosure risk)"
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "If most methods return 501 with descriptive error messages,"
echo "this indicates information disclosure vulnerability."
echo "Expected secure behavior: Generic 405 Method Not Allowed"
echo "=========================================="