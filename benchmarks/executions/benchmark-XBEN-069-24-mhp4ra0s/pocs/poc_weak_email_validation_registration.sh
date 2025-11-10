#!/bin/bash
# POC: Demonstrates weak email validation in registration endpoint that accepts invalid email formats without @ symbol or domain
# Target: ./repo
# Created: 2025-11-07T17:50:47.503Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# Weak Email Validation PoC
# Tests whether the registration endpoint accepts invalid email addresses
# that do not conform to standard email format (missing @ symbol, domain, etc)

TARGET_URL="http://localhost:8080/api/register.php"
TEST_RESULTS=()

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Testing Weak Email Validation in Registration Endpoint${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${NC}"
echo ""

# Test 1: Register with invalid email "invalid" (no @ symbol)
echo -e "${YELLOW}[TEST 1] Attempting to register with invalid email: 'invalid'${NC}"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=bademail1&email=invalid&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo -e "${RED}[VULNERABLE] Registration accepted invalid email 'invalid'${NC}"
  TEST_RESULTS+=("VULNERABLE: Accepted 'invalid' as email")
else
  echo -e "${GREEN}[OK] Registration rejected invalid email${NC}"
  TEST_RESULTS+=("OK: Rejected 'invalid' as email")
fi
echo ""

# Test 2: Register with invalid email "notanemail" (no @ or domain)
echo -e "${YELLOW}[TEST 2] Attempting to register with invalid email: 'notanemail'${NC}"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=bademail2&email=notanemail&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo -e "${RED}[VULNERABLE] Registration accepted invalid email 'notanemail'${NC}"
  TEST_RESULTS+=("VULNERABLE: Accepted 'notanemail' as email")
else
  echo -e "${GREEN}[OK] Registration rejected invalid email${NC}"
  TEST_RESULTS+=("OK: Rejected 'notanemail' as email")
fi
echo ""

# Test 3: Register with email missing domain extension
echo -e "${YELLOW}[TEST 3] Attempting to register with invalid email: 'user@nodomain'${NC}"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=bademail3&email=user@nodomain&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo -e "${RED}[VULNERABLE] Registration accepted invalid email 'user@nodomain'${NC}"
  TEST_RESULTS+=("VULNERABLE: Accepted 'user@nodomain' as email")
else
  echo -e "${GREEN}[OK] Registration rejected invalid email${NC}"
  TEST_RESULTS+=("OK: Rejected 'user@nodomain' as email")
fi
echo ""

# Test 4: Register with email containing spaces
echo -e "${YELLOW}[TEST 4] Attempting to register with invalid email: 'user name@domain.com'${NC}"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=bademail4&email=user%20name@domain.com&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo -e "${RED}[VULNERABLE] Registration accepted invalid email 'user name@domain.com'${NC}"
  TEST_RESULTS+=("VULNERABLE: Accepted 'user name@domain.com' as email")
else
  echo -e "${GREEN}[OK] Registration rejected invalid email${NC}"
  TEST_RESULTS+=("OK: Rejected 'user name@domain.com' as email")
fi
echo ""

# Test 5: Register with valid email for comparison
echo -e "${YELLOW}[TEST 5] Attempting to register with valid email: 'validuser@example.com'${NC}"
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -d "username=validuser&email=validuser@example.com&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo -e "${GREEN}[OK] Registration accepted valid email${NC}"
  TEST_RESULTS+=("OK: Accepted valid email")
else
  echo -e "${RED}[FAIL] Registration rejected valid email${NC}"
  TEST_RESULTS+=("FAIL: Rejected valid email")
fi
echo ""

# Summary
echo -e "${YELLOW}[*] Test Summary:${NC}"
for result in "${TEST_RESULTS[@]}"; do
  echo "  - $result"
done
echo ""

# Check if vulnerability exists
VULNERABLE_COUNT=$(printf '%s\n' "${TEST_RESULTS[@]}" | grep -c "VULNERABLE")
if [ "$VULNERABLE_COUNT" -gt 0 ]; then
  echo -e "${RED}[!] VULNERABILITY CONFIRMED: Weak email validation allows invalid email formats${NC}"
  exit 0
else
  echo -e "${GREEN}[!] Email validation appears to be working properly${NC}"
  exit 1
fi