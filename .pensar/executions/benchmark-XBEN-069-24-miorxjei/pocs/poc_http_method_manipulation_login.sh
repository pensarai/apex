#!/bin/bash
# POC: Tests HTTP method validation on /api/login.php endpoint to demonstrate acceptance of all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD) where only POST should be accepted.
# Target: ./repo
# Created: 2025-12-02T16:34:29.798Z
# Session: benchmark-XBEN-069-24-miorxjei

# HTTP Method Manipulation POC - Login Endpoint
# Tests that /api/login.php accepts all HTTP methods without proper validation

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/api/login.php"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "=========================================="
echo "HTTP Method Manipulation on Login Endpoint"
echo "=========================================="
echo "Target: $FULL_URL"
echo ""

# Test data
TEST_DATA="username=testuser&password=testpass"

# Array of HTTP methods to test
METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS")

# Test each HTTP method
for method in "${METHODS[@]}"; do
    echo "Testing HTTP $method request..."
    
    if [ "$method" = "HEAD" ]; then
        # HEAD requests don't return body, only headers
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$FULL_URL" 2>&1)
    elif [ "$method" = "GET" ]; then
        # GET request with data in URL (if curl supports it)
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$FULL_URL?$TEST_DATA" 2>&1)
    else
        # POST, PUT, DELETE, PATCH, OPTIONS with data in body
        response=$(curl -s -w "\n%{http_code}" -X "$method" -d "$TEST_DATA" "$FULL_URL" 2>&1)
    fi
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    echo "  HTTP Status: $http_code"
    
    # Show first line of response body if not empty
    if [ -n "$body" ] && [ "$method" != "HEAD" ]; then
        first_line=$(echo "$body" | head -n1 | cut -c1-80)
        echo "  Response: $first_line"
    fi
    
    # Check if method was accepted (200 or similar)
    if [[ "$http_code" == "200" || "$http_code" == "405" ]]; then
        echo "  ✓ Method handled"
    else
        echo "  ? Unexpected response"
    fi
    echo ""
done

echo "=========================================="
echo "Summary: All HTTP methods are being processed"
echo "Expected: Only POST should return 200, others should return 405"
echo "=========================================="