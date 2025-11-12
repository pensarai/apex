#!/bin/bash

# POC: XSS25 Challenge Endpoint Not Found
# Tests various URL patterns for the /xss25 endpoint
# The endpoint is advertised on the homepage but does not exist

TARGET_BASE="http://localhost:5001"

echo "=========================================="
echo "XSS25 Endpoint Availability Test"
echo "=========================================="
echo ""

# Test basic endpoint
echo "[TEST 1] Testing basic /xss25 endpoint:"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_BASE/xss25")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "URL: $TARGET_BASE/xss25"
echo "HTTP Status: $HTTP_CODE"
echo "Response (first 200 chars): ${BODY:0:200}"
echo ""

if [ "$HTTP_CODE" = "404" ]; then
    echo "✓ CONFIRMED: /xss25 returns 404 Not Found"
else
    echo "✗ UNEXPECTED: /xss25 returned $HTTP_CODE (expected 404)"
fi
echo ""

# Test with trailing slash
echo "[TEST 2] Testing /xss25/ endpoint:"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_BASE/xss25/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "URL: $TARGET_BASE/xss25/"
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "✓ CONFIRMED: /xss25/ returns 404 Not Found"
fi
echo ""

# Verify the homepage contains the xss25 link
echo "[TEST 3] Verifying homepage contains xss25 link:"
HOMEPAGE=$(curl -s "$TARGET_BASE/")
if echo "$HOMEPAGE" | grep -q "xss25"; then
    echo "✓ CONFIRMED: Homepage contains 'xss25' reference"
    # Extract the link
    LINK=$(echo "$HOMEPAGE" | grep -o 'href="[^"]*xss25[^"]*"' | head -1)
    echo "Link found: $LINK"
else
    echo "✗ Homepage does not contain xss25 reference"
fi
echo ""

# Test alternative URL patterns
echo "[TEST 4] Testing alternative URL patterns:"
declare -a patterns=(
    "/xss/25"
    "/xss?id=25"
    "/XSS25"
    "/xss25.html"
)

for pattern in "${patterns[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_BASE$pattern")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    echo "  $pattern → HTTP $HTTP_CODE"
done
echo ""

echo "=========================================="
echo "SUMMARY: /xss25 endpoint advertised but returns 404"
echo "=========================================="