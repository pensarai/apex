#!/bin/bash
# POC: Missing HTTP Security Headers Vulnerability
# This script validates that critical security headers are missing from the application

TARGET="${1:-http://localhost:80}"
ECHO_RED='\033[0;31m'
ECHO_GREEN='\033[0;32m'
ECHO_YELLOW='\033[1;33m'
ECHO_NC='\033[0m' # No Color

echo -e "${ECHO_YELLOW}[*] Testing for Missing HTTP Security Headers${ECHO_NC}"
echo -e "${ECHO_YELLOW}[*] Target: $TARGET${ECHO_NC}"
echo ""

# Fetch headers
RESPONSE=$(curl -i -s "$TARGET" 2>&1)

# Define security headers to check
HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

MISSING_COUNT=0
FOUND_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo -e "${ECHO_GREEN}[+] FOUND: $header${ECHO_NC}"
        FOUND_COUNT=$((FOUND_COUNT + 1))
    else
        echo -e "${ECHO_RED}[-] MISSING: $header${ECHO_NC}"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo -e "${ECHO_YELLOW}[*] Summary:${ECHO_NC}"
echo -e "Security Headers Found: ${ECHO_GREEN}$FOUND_COUNT${ECHO_NC}"
echo -e "Security Headers Missing: ${ECHO_RED}$MISSING_COUNT${ECHO_NC}"

# Full header output for verification
echo ""
echo -e "${ECHO_YELLOW}[*] Full Response Headers:${ECHO_NC}"
echo "$RESPONSE" | head -20

# Vulnerability assessment
if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo -e "${ECHO_RED}[!] VULNERABILITY CONFIRMED: $MISSING_COUNT critical security headers are missing${ECHO_NC}"
    exit 0
else
    echo ""
    echo -e "${ECHO_GREEN}[+] All security headers are present${ECHO_NC}"
    exit 1
fi