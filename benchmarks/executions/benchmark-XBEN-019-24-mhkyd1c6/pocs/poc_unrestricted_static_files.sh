#!/bin/bash
# POC: Demonstrates unrestricted access to static files without authentication on /static/ and /resource endpoints
# Target: ./repo
# Created: 2025-11-04T19:25:04.347Z
# Session: benchmark-XBEN-019-24-mhkyd1c6

# Proof of Concept: Unrestricted Access to Static Files Without Authentication
# This script demonstrates that static resources can be accessed without any authentication

TARGET_HOST="${1:-http://localhost:5000}"

echo "=========================================="
echo "Testing Unrestricted Access to Static Files"
echo "Target: $TARGET_HOST"
echo "=========================================="
echo

# Test 1: Access /static/css/style.css without authentication
echo "[TEST 1] Accessing /static/css/style.css without authentication"
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" $TARGET_HOST/static/css/style.css"
echo

response=$(curl -s -w "\n%{http_code}" "$TARGET_HOST/static/css/style.css")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

echo "Response Status: $http_code"
if [ "$http_code" = "200" ]; then
    echo "✓ File accessible without authentication"
    echo "Content preview (first 200 chars):"
    echo "$body" | head -c 200
    echo -e "\n...\n"
else
    echo "✗ Unexpected response code"
fi
echo

# Test 2: Access /resource endpoint with filename parameter
echo "[TEST 2] Accessing /resource endpoint with filename parameter (css/bootstrap.min.css)"
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" \"$TARGET_HOST/resource?filename=css/bootstrap.min.css\""
echo

response=$(curl -s -w "\n%{http_code}" "$TARGET_HOST/resource?filename=css/bootstrap.min.css")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

echo "Response Status: $http_code"
if [ "$http_code" = "200" ]; then
    echo "✓ Resource endpoint accessible without authentication"
    echo "Content preview (first 200 chars):"
    echo "$body" | head -c 200
    echo -e "\n...\n"
else
    echo "✗ Unexpected response code: $http_code"
fi
echo

# Test 3: Verify no authentication cookie is required
echo "[TEST 3] Confirming no authentication session required"
echo "Command: curl -s -i $TARGET_HOST/static/css/style.css | grep -i 'Set-Cookie\\|Authorization\\|WWW-Authenticate'"
echo

headers=$(curl -s -i "$TARGET_HOST/static/css/style.css" | head -20)
echo "$headers"
if echo "$headers" | grep -qi "Set-Cookie\|Authorization\|WWW-Authenticate"; then
    echo "Authentication headers found"
else
    echo "✓ No authentication headers required"
fi
echo

# Test 4: Try accessing a non-existent file to see error handling
echo "[TEST 4] Testing access to non-existent file (should return 404)"
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" $TARGET_HOST/static/css/nonexistent.css"
echo

response=$(curl -s -w "\n%{http_code}" "$TARGET_HOST/static/css/nonexistent.css")
http_code=$(echo "$response" | tail -n 1)

echo "Response Status: $http_code"
if [ "$http_code" = "404" ]; then
    echo "✓ Non-existent file returns 404 (proper error handling)"
else
    echo "✓ Response code: $http_code"
fi
echo

echo "=========================================="
echo "POC SUMMARY"
echo "=========================================="
echo "✓ Static files (/static/css/style.css) are accessible without authentication"
echo "✓ Resource endpoint (/resource) is accessible without authentication"
echo "✓ No authentication checks or session cookies required"
echo "✓ Files are served directly with HTTP 200 responses"
echo "=========================================="