#!/bin/bash

# POC: Missing Secure and SameSite Flags on Session Cookie
# This script demonstrates that the session cookie lacks critical security flags

TARGET="http://localhost:8080"
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e "${BOLD}=== POC: Missing Secure and SameSite Flags on Session Cookie ===${RESET}\n"

echo -e "${BOLD}[*] Step 1: Performing login to obtain session cookie${RESET}"
RESPONSE=$(curl -i -s -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "$RESPONSE" | head -15
echo ""

echo -e "${BOLD}[*] Step 2: Extracting Set-Cookie header${RESET}"
COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | tr -d '\r')

if [ -z "$COOKIE_HEADER" ]; then
    echo -e "${RED}[!] ERROR: No Set-Cookie header found${RESET}"
    exit 1
fi

echo -e "Found: ${YELLOW}$COOKIE_HEADER${RESET}\n"

echo -e "${BOLD}[*] Step 3: Analyzing cookie security flags${RESET}"
echo "-------------------------------------------"

# Check for each security flag
HTTPONLY_PRESENT=false
SECURE_PRESENT=false
SAMESITE_PRESENT=false

if echo "$COOKIE_HEADER" | grep -iq "HttpOnly"; then
    HTTPONLY_PRESENT=true
fi

if echo "$COOKIE_HEADER" | grep -iq "Secure"; then
    SECURE_PRESENT=true
fi

if echo "$COOKIE_HEADER" | grep -iq "SameSite"; then
    SAMESITE_PRESENT=true
fi

# Report findings
echo -e "HttpOnly flag:  $([ "$HTTPONLY_PRESENT" = true ] && echo -e "${GREEN}PRESENT ✓${RESET}" || echo -e "${RED}MISSING ✗${RESET}")"
echo -e "Secure flag:    $([ "$SECURE_PRESENT" = true ] && echo -e "${GREEN}PRESENT ✓${RESET}" || echo -e "${RED}MISSING ✗${RESET}")"
echo -e "SameSite attr:  $([ "$SAMESITE_PRESENT" = true ] && echo -e "${GREEN}PRESENT ✓${RESET}" || echo -e "${RED}MISSING ✗${RESET}")"
echo ""

echo -e "${BOLD}[*] Step 4: Security Impact Assessment${RESET}"
echo "-------------------------------------------"

VULNERABILITY_FOUND=false

if [ "$SECURE_PRESENT" = false ]; then
    echo -e "${RED}[!] VULNERABILITY: Missing Secure flag${RESET}"
    echo "    Impact: Session cookie can be transmitted over unencrypted HTTP"
    echo "    Risk: Man-in-the-middle attacks, session hijacking"
    echo ""
    VULNERABILITY_FOUND=true
fi

if [ "$SAMESITE_PRESENT" = false ]; then
    echo -e "${RED}[!] VULNERABILITY: Missing SameSite attribute${RESET}"
    echo "    Impact: Application vulnerable to CSRF attacks"
    echo "    Risk: Malicious sites can make authenticated requests"
    echo ""
    VULNERABILITY_FOUND=true
fi

echo -e "${BOLD}[*] Step 5: Recommended Cookie Configuration${RESET}"
echo "-------------------------------------------"
echo "Current cookie: $COOKIE_HEADER"
echo ""
echo -e "Secure cookie should be:"
echo -e "${GREEN}Set-Cookie: session=<value>; Secure; HttpOnly; SameSite=Strict; Path=/${RESET}"
echo ""

if [ "$VULNERABILITY_FOUND" = true ]; then
    echo -e "${BOLD}${RED}[!] VULNERABILITY CONFIRMED${RESET}"
    echo -e "The session cookie is missing critical security flags."
    exit 0
else
    echo -e "${BOLD}${GREEN}[✓] Cookie is properly configured${RESET}"
    exit 1
fi