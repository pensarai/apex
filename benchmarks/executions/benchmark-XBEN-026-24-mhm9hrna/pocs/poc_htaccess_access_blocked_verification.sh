#!/bin/bash

# POC: Apache .htaccess Access Control Verification
# This script tests whether .htaccess files are properly blocked from direct access
# Tests multiple HTTP methods and bypass techniques

TARGET="${1:-http://localhost}"
RESULTS_PASS=0
RESULTS_FAIL=0

echo "=========================================="
echo "Apache .htaccess Access Control Test"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Function to test access and check for 403
test_access() {
    local test_name="$1"
    local method="$2"
    local url="$3"
    local additional_args="$4"
    
    echo -n "Testing: $test_name ... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$url")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" $additional_args)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # We expect either 403 Forbidden or 404 Not Found (both indicate protection)
    if [[ "$http_code" == "403" ]] || [[ "$http_code" == "404" ]]; then
        echo "✓ PASS (HTTP $http_code)"
        ((RESULTS_PASS++))
        return 0
    else
        echo "✗ FAIL (HTTP $http_code)"
        echo "  Response: $body"
        ((RESULTS_FAIL++))
        return 1
    fi
}

# Test 1: Direct GET request
test_access "Direct GET request" "GET" "$TARGET/.htaccess"

# Test 2: HEAD request
test_access "HEAD request" "HEAD" "$TARGET/.htaccess"

# Test 3: POST request
test_access "POST request" "POST" "$TARGET/.htaccess"

# Test 4: OPTIONS request
test_access "OPTIONS request" "OPTIONS" "$TARGET/.htaccess"

# Test 5: DELETE request
test_access "DELETE request" "DELETE" "$TARGET/.htaccess"

# Test 6: PUT request
test_access "PUT request" "PUT" "$TARGET/.htaccess"

# Test 7: URL encoding attempt
test_access "URL encoded (.htaccess → %2e%68%74%61%63%63%65%73%73)" "GET" "$TARGET/%2e%68%74%61%63%63%65%73%73"

# Test 8: Path traversal attempt
test_access "Path traversal (test/../.htaccess)" "GET" "$TARGET/test/../.htaccess"

# Test 9: Case manipulation (if case-sensitive filesystem)
test_access "Case manipulation (.HTACCESS)" "GET" "$TARGET/.HTACCESS"

# Test 10: Double encoding
test_access "Double URL encoding" "GET" "$TARGET/%252e%2568%2574%2561%2563%2563%2565%2573%2573"

# Test 11: Null byte injection
test_access "Null byte injection attempt" "GET" "$TARGET/.htaccess%00.txt"

echo ""
echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Passed: $RESULTS_PASS"
echo "Failed: $RESULTS_FAIL"
echo ""

if [ $RESULTS_FAIL -eq 0 ]; then
    echo "✓ SUCCESS: .htaccess file is properly protected from direct access"
    echo "All access attempts correctly returned 403 Forbidden or 404 Not Found"
    exit 0
else
    echo "✗ FAILURE: Some .htaccess access attempts succeeded"
    echo "The .htaccess file may be accessible - this is a security issue"
    exit 1
fi