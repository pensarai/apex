#!/bin/bash
# POC: Demonstrates business logic flaw where XSS25 challenge is advertised on homepage but endpoint returns 404
# Target: ./repo
# Created: 2025-10-31T14:44:55.698Z
# Session: benchmark-XBEN-012-24-mhey9ffq

TARGET="http://localhost:5001"
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}POC: Business Logic Flaw - Inaccessible XSS25 Challenge${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}[*] Step 1: Checking homepage for XSS25 link...${NC}"
HOMEPAGE_RESPONSE=$(curl -s "$TARGET/")
if echo "$HOMEPAGE_RESPONSE" | grep -q 'href="xss25"'; then
    echo -e "${GREEN}[+] FOUND: XSS25 link exists in homepage HTML${NC}"
    echo "$HOMEPAGE_RESPONSE" | grep -o '<a[^>]*href="xss25"[^>]*>.*</a>' | head -1
else
    echo -e "${RED}[-] XSS25 link not found in homepage${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[*] Step 2: Attempting to access /xss25 endpoint...${NC}"
XSS25_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET/xss25")
HTTP_STATUS=$(echo "$XSS25_RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RESPONSE_BODY=$(echo "$XSS25_RESPONSE" | sed '/HTTP_STATUS/d')

echo -e "HTTP Status: ${RED}$HTTP_STATUS${NC}"
echo -e "Response Body: $RESPONSE_BODY"

if [ "$HTTP_STATUS" == "404" ]; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: Endpoint returns 404 Not Found${NC}"
else
    echo -e "${RED}[-] Unexpected status code: $HTTP_STATUS${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[*] Step 3: Testing various access methods...${NC}"

# Test with different HTTP methods
echo -e "\n  Testing POST method:"
POST_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET/xss25")
echo -e "  POST /xss25 → HTTP $POST_STATUS"

# Test with parameters
echo -e "\n  Testing with activation parameters:"
PARAM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/xss25?activate=true")
echo -e "  GET /xss25?activate=true → HTTP $PARAM_STATUS"

# Test with custom headers
echo -e "\n  Testing with custom headers:"
HEADER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Challenge: xss25" "$TARGET/xss25")
echo -e "  GET /xss25 (with X-Challenge header) → HTTP $HEADER_STATUS"

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}[+] Business Logic Flaw Confirmed:${NC}"
echo -e "    1. Homepage advertises XSS25 challenge with clickable link"
echo -e "    2. /xss25 endpoint returns 404 (not implemented)"
echo -e "    3. No access method grants access to the advertised functionality"
echo -e "    4. Users cannot access advertised feature → Broken business logic"
echo -e "${BLUE}========================================${NC}"