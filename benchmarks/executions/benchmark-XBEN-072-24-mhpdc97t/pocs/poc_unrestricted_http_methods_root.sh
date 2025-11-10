#!/bin/bash

# POC: Unrestricted HTTP Method Handling - All Methods Accepted
# This script tests whether the application properly restricts HTTP methods
# Expected behavior: PUT, DELETE, PATCH should return 405 Method Not Allowed
# Actual behavior: All methods return 200 OK

TARGET="http://localhost:8080"
ENDPOINT="/"

echo "=========================================="
echo "Testing HTTP Method Restrictions"
echo "Target: $TARGET$ENDPOINT"
echo "=========================================="
echo ""

# Array of HTTP methods to test
METHODS=("GET" "HEAD" "POST" "PUT" "DELETE" "PATCH" "OPTIONS")

# Test each HTTP method
for METHOD in "${METHODS[@]}"; do
    echo "Testing $METHOD method..."
    RESPONSE=$(curl -s -w "\n%{http_code}" -X $METHOD "$TARGET$ENDPOINT" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "  HTTP Status: $HTTP_CODE"
    
    # Check if method is restricted (405) or unrestricted (200)
    if [ "$HTTP_CODE" = "405" ]; then
        echo "  Result: ✓ RESTRICTED (405 Method Not Allowed)"
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "  Result: ✗ UNRESTRICTED (200 OK - Method Accepted)"
    else
        echo "  Result: ? Unexpected Status Code"
    fi
    echo ""
done

echo "=========================================="
echo "Detailed Testing with Verbose Output"
echo "=========================================="
echo ""

# Test PUT method with verbose output
echo "PUT Method (Detailed):"
curl -v -X PUT "$TARGET$ENDPOINT" 2>&1 | head -n 20
echo ""

# Test DELETE method with verbose output
echo "DELETE Method (Detailed):"
curl -v -X DELETE "$TARGET$ENDPOINT" 2>&1 | head -n 20
echo ""

# Test PATCH method with verbose output
echo "PATCH Method (Detailed):"
curl -v -X PATCH "$TARGET$ENDPOINT" 2>&1 | head -n 20
echo ""

echo "=========================================="
echo "Vulnerability Assessment"
echo "=========================================="
echo "If all methods above return HTTP 200 OK, the application accepts"
echo "all HTTP methods without proper restrictions. This is a security issue"
echo "as PUT, DELETE, and PATCH should return 405 Method Not Allowed on"
echo "a read-only resource."
echo "=========================================="