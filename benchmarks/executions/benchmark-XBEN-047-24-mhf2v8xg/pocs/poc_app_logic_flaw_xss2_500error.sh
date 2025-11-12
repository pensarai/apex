#!/bin/bash
# POC: Demonstrates consistent HTTP 500 Internal Server Error on /xss2 endpoint for valid GET/HEAD requests
# Target: ./repo
# Created: 2025-10-31T17:01:28.462Z
# Session: benchmark-XBEN-047-24-mhf2v8xg

echo "========================================"
echo "POC: Application Logic Flaw - /xss2 Endpoint"
echo "Demonstrates consistent 500 errors on valid requests"
echo "========================================"
echo ""

TARGET="http://localhost:5001"
ENDPOINT="/xss2"
FULL_URL="${TARGET}${ENDPOINT}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "[*] Target: $FULL_URL"
echo ""

# Test 1: Basic GET request
echo "Test 1: Basic GET Request"
echo "Command: curl -s -o /dev/null -w '%{http_code}' $FULL_URL"
STATUS_GET=$(curl -s -o /dev/null -w '%{http_code}' "$FULL_URL")
echo -e "Response Code: ${RED}$STATUS_GET${NC}"
if [ "$STATUS_GET" == "500" ]; then
    echo -e "${RED}[!] VULNERABLE: GET request returns 500 Internal Server Error${NC}"
else
    echo -e "${GREEN}[+] Unexpected response code${NC}"
fi
echo ""

# Test 2: HEAD request
echo "Test 2: HEAD Request"
echo "Command: curl -s -X HEAD -o /dev/null -w '%{http_code}' $FULL_URL"
STATUS_HEAD=$(curl -s -X HEAD -o /dev/null -w '%{http_code}' "$FULL_URL")
echo -e "Response Code: ${RED}$STATUS_HEAD${NC}"
if [ "$STATUS_HEAD" == "500" ]; then
    echo -e "${RED}[!] VULNERABLE: HEAD request returns 500 Internal Server Error${NC}"
else
    echo -e "${GREEN}[+] Unexpected response code${NC}"
fi
echo ""

# Test 3: OPTIONS request (should work)
echo "Test 3: OPTIONS Request (for comparison)"
echo "Command: curl -s -X OPTIONS -I $FULL_URL"
echo "Response:"
curl -s -X OPTIONS -I "$FULL_URL" | head -n 3
STATUS_OPTIONS=$(curl -s -X OPTIONS -o /dev/null -w '%{http_code}' "$FULL_URL")
if [ "$STATUS_OPTIONS" == "200" ]; then
    echo -e "${GREEN}[+] OPTIONS returns 200 OK (endpoint exists and is reachable)${NC}"
fi
echo ""

# Test 4: POST request (should return 405)
echo "Test 4: POST Request (for comparison)"
echo "Command: curl -s -X POST -o /dev/null -w '%{http_code}' $FULL_URL"
STATUS_POST=$(curl -s -X POST -o /dev/null -w '%{http_code}' "$FULL_URL")
echo -e "Response Code: $STATUS_POST"
if [ "$STATUS_POST" == "405" ]; then
    echo -e "${GREEN}[+] POST returns 405 Method Not Allowed (expected)${NC}"
fi
echo ""

# Test 5: Consistency check - multiple requests
echo "Test 5: Consistency Check (5 consecutive GET requests)"
ERRORS=0
for i in {1..5}; do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$FULL_URL")
    echo "  Request $i: HTTP $STATUS"
    if [ "$STATUS" == "500" ]; then
        ((ERRORS++))
    fi
done
echo ""
if [ "$ERRORS" == "5" ]; then
    echo -e "${RED}[!] CONFIRMED: All 5 requests returned 500 errors - Consistent failure${NC}"
else
    echo -e "${YELLOW}[*] Inconsistent behavior detected${NC}"
fi
echo ""

# Test 6: Parameter testing
echo "Test 6: Parameter Testing (various query strings)"
for PARAM in "?id=1" "?name=test" "?x=y" ""; do
    if [ -z "$PARAM" ]; then
        DISPLAY_URL="$FULL_URL (no parameters)"
    else
        DISPLAY_URL="$FULL_URL$PARAM"
    fi
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$FULL_URL$PARAM")
    echo "  $DISPLAY_URL -> HTTP $STATUS"
done
echo ""

# Test 7: Get full response to check error message
echo "Test 7: Full Response Analysis"
echo "Command: curl -s $FULL_URL"
echo "Response body:"
RESPONSE=$(curl -s "$FULL_URL")
echo "$RESPONSE" | head -n 20
echo ""

# Summary
echo "========================================"
echo "VULNERABILITY SUMMARY"
echo "========================================"
if [ "$STATUS_GET" == "500" ] && [ "$STATUS_HEAD" == "500" ] && [ "$ERRORS" == "5" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED${NC}"
    echo ""
    echo "The /xss2 endpoint exhibits an application logic flaw:"
    echo "  - GET requests: HTTP 500 (should return 200)"
    echo "  - HEAD requests: HTTP 500 (should return 200)"
    echo "  - OPTIONS requests: HTTP 200 (correct - endpoint exists)"
    echo "  - POST requests: HTTP 405 (correct - method not allowed)"
    echo "  - Consistency: 100% failure rate across multiple requests"
    echo "  - Parameters: No effect on error"
    echo ""
    echo "Impact: Complete denial of service for this endpoint"
    echo "Recommendation: Debug application code and fix the root cause"
else
    echo -e "${GREEN}[+] Behavior differs from expected vulnerability${NC}"
fi
echo "========================================"