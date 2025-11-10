#!/bin/bash

# POC: No Accessible Endpoints - Complete Application Lockdown
# Tests comprehensive endpoint enumeration to verify all requests return 404

TARGET="http://localhost:2280"
FAILED=0
PASSED=0

echo "=========================================="
echo "POC: Complete Application Lockdown (404)"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test function
test_endpoint() {
    local method=$1
    local path=$2
    local data=$3
    local description=$4
    
    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$TARGET$path" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$data" "$TARGET$path" 2>/dev/null)
    fi
    
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | head -1)
    
    if [ "$http_code" = "404" ]; then
        echo "✓ PASS: $description"
        echo "  Method: $method | Path: $path | Status: $http_code"
        ((PASSED++))
    else
        echo "✗ FAIL: $description"
        echo "  Expected: 404, Got: $http_code | Path: $path"
        ((FAILED++))
    fi
}

# Test basic paths
echo "Testing basic paths with GET requests:"
echo "---"
test_endpoint "GET" "/" "root path"
test_endpoint "GET" "/api" "/api endpoint"
test_endpoint "GET" "/admin" "/admin endpoint"
test_endpoint "GET" "/users" "/users endpoint"
test_endpoint "GET" "/health" "/health endpoint"
test_endpoint "GET" "/ping" "/ping endpoint"
test_endpoint "GET" "/test" "/test endpoint"
test_endpoint "GET" "/query" "/query endpoint"
test_endpoint "GET" "/graphql" "/graphql endpoint"

echo ""
echo "Testing numeric and nested paths:"
echo "---"
test_endpoint "GET" "/1" "numeric path /1"
test_endpoint "GET" "/123" "numeric path /123"
test_endpoint "GET" "/id/1" "nested path /id/1"
test_endpoint "GET" "/user/1" "nested path /user/1"
test_endpoint "GET" "/x/y/z" "deeply nested path /x/y/z"

echo ""
echo "Testing query parameters:"
echo "---"
test_endpoint "GET" "/?query=test" "root with query parameter"
test_endpoint "GET" "/api?key=value" "/api with query parameter"
test_endpoint "GET" "/test?id=1&name=test" "/test with multiple parameters"

echo ""
echo "Testing HTTP Methods:"
echo "---"
test_endpoint "POST" "/" "POST to root"
test_endpoint "POST" "/api" "POST to /api"
test_endpoint "PUT" "/test" "PUT to /test"
test_endpoint "DELETE" "/user/1" "DELETE to /user/1"
test_endpoint "PATCH" "/test" "PATCH to /test"

echo ""
echo "Testing with request bodies:"
echo "---"
test_endpoint "POST" "/api" '{"key":"value"}' "POST with JSON body"
test_endpoint "POST" "/test" '{"data":"test"}' "POST with JSON data"
test_endpoint "PUT" "/user/1" '{"name":"updated"}' "PUT with JSON body"

echo ""
echo "Testing file-like paths:"
echo "---"
test_endpoint "GET" "/test.json" "/test.json"
test_endpoint "GET" "/test.xml" "/test.xml"
test_endpoint "GET" "/test.php" "/test.php"
test_endpoint "GET" "/.git" "/.git endpoint"
test_endpoint "GET" "/.env" "/.env endpoint"
test_endpoint "GET" "/config" "/config endpoint"

echo ""
echo "Testing edge cases:"
echo "---"
test_endpoint "GET" "/;/" "/;/ path"
test_endpoint "GET" "/..%00/" "/..%00/ path traversal"
test_endpoint "GET" "/test//" "/test// double slash"

echo ""
echo "=========================================="
echo "Test Results Summary:"
echo "=========================================="
echo "PASSED: $PASSED"
echo "FAILED: $FAILED"
echo ""

if [ $FAILED -eq 0 ] && [ $PASSED -gt 20 ]; then
    echo "✓ VULNERABILITY CONFIRMED: All endpoints return 404"
    echo "  Application is completely locked down - no accessible endpoints"
    exit 0
else
    echo "✗ Some endpoints returned non-404 responses"
    exit 1
fi