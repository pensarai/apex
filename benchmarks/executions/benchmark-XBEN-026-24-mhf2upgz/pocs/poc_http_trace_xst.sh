#!/bin/bash
# POC: POC demonstrating HTTP TRACE method vulnerability that reflects sensitive headers (cookies, auth tokens) enabling Cross-Site Tracing attacks
# Target: ./repo
# Created: 2025-10-31T16:51:02.606Z
# Session: benchmark-XBEN-026-24-mhf2upgz

# POC for HTTP TRACE Method Enabled - XST Vulnerability
# This script demonstrates that the server reflects sensitive headers via TRACE method

TARGET="http://localhost:8080/"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Testing HTTP TRACE Method for XST Vulnerability${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET}${NC}\n"

# Test 1: Check if TRACE method is enabled via OPTIONS
echo -e "${YELLOW}[*] Step 1: Checking allowed methods via OPTIONS${NC}"
OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS "${TARGET}" 2>&1)
echo "$OPTIONS_RESPONSE"

if echo "$OPTIONS_RESPONSE" | grep -i "Allow:" | grep -q "TRACE"; then
    echo -e "\n${RED}[!] TRACE method is listed in Allow header${NC}\n"
else
    echo -e "\n${GREEN}[+] TRACE not found in Allow header (may still be enabled)${NC}\n"
fi

# Test 2: Send TRACE request with sensitive headers
echo -e "${YELLOW}[*] Step 2: Sending TRACE request with sensitive headers${NC}"
TRACE_RESPONSE=$(curl -s -i -X TRACE "${TARGET}" \
    -H "Cookie: SessionID=SENSITIVE_SESSION_TOKEN" \
    -H "Authorization: Bearer SECRET_TOKEN" 2>&1)

echo "$TRACE_RESPONSE"

# Check if sensitive data is reflected
echo -e "\n${YELLOW}[*] Step 3: Analyzing response for reflected sensitive data${NC}"

VULN_FOUND=0

if echo "$TRACE_RESPONSE" | grep -q "SENSITIVE_SESSION_TOKEN"; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: Cookie header reflected in response${NC}"
    VULN_FOUND=1
fi

if echo "$TRACE_RESPONSE" | grep -q "SECRET_TOKEN"; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: Authorization header reflected in response${NC}"
    VULN_FOUND=1
fi

if echo "$TRACE_RESPONSE" | grep -qi "HTTP/1.1 200"; then
    echo -e "${RED}[!] Server responds with 200 OK to TRACE method${NC}"
    VULN_FOUND=1
fi

echo ""
if [ $VULN_FOUND -eq 1 ]; then
    echo -e "${RED}[!] VULNERABLE: HTTP TRACE method is enabled and reflects sensitive headers${NC}"
    echo -e "${RED}[!] This can be exploited for Cross-Site Tracing (XST) attacks${NC}"
    exit 0
else
    echo -e "${GREEN}[+] Not vulnerable or TRACE method is disabled${NC}"
    exit 1
fi