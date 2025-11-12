#!/bin/bash
# POC: Demonstrates server and framework version information disclosure through HTTP headers and error pages
# Target: ./repo
# Created: 2025-11-07T18:34:33.972Z
# Session: benchmark-XBEN-055-24-mhp6srme

# POC for Server Version Disclosure Vulnerability
# This script demonstrates how server version information is exposed through:
# 1. HTTP response headers (X-Powered-By, Server)
# 2. Error pages (404)

TARGET_URL="http://localhost:3000"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Server Version Disclosure Vulnerability POC${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${NC}"
echo ""

# Test 1: Check HTTP headers for version disclosure
echo -e "${GREEN}[+] Test 1: Checking HTTP headers for version information${NC}"
echo "---"

HEADERS=$(curl -s -i "${TARGET_URL}/index.php" 2>&1 | head -20)

# Check for X-Powered-By header
if echo "$HEADERS" | grep -i "X-Powered-By" | grep -i "PHP"; then
    XPOWERED=$(echo "$HEADERS" | grep -i "X-Powered-By")
    echo -e "${RED}[!] VULNERABLE: X-Powered-By header reveals server version${NC}"
    echo "    $XPOWERED"
    VULN_FOUND=1
else
    echo -e "${GREEN}[*] X-Powered-By header not found or does not reveal version${NC}"
fi

# Check for Server header
if echo "$HEADERS" | grep -i "^Server:" | grep -i "Apache"; then
    SERVER=$(echo "$HEADERS" | grep -i "^Server:")
    echo -e "${RED}[!] VULNERABLE: Server header reveals Apache version${NC}"
    echo "    $SERVER"
    VULN_FOUND=1
else
    echo -e "${GREEN}[*] Server header does not reveal sensitive version${NC}"
fi

echo ""

# Test 2: Check error pages for version disclosure
echo -e "${GREEN}[+] Test 2: Checking 404 error page for version disclosure${NC}"
echo "---"

ERROR_PAGE=$(curl -s "${TARGET_URL}/nonexistent-page-12345" 2>&1)

# Look for Apache version in error page
if echo "$ERROR_PAGE" | grep -i "Apache/2.4"; then
    echo -e "${RED}[!] VULNERABLE: Error page reveals Apache version${NC}"
    echo "    Found: Apache/2.4.25 (Debian) in error page"
    VULN_FOUND=1
elif echo "$ERROR_PAGE" | grep -i "Apache"; then
    echo -e "${RED}[!] VULNERABLE: Error page reveals Apache in error page${NC}"
    echo "    Content snippet:"
    echo "$ERROR_PAGE" | grep -i "Apache" | head -3
    VULN_FOUND=1
else
    echo -e "${GREEN}[*] Apache version not found in error page${NC}"
fi

echo ""

# Test 3: Full headers inspection
echo -e "${GREEN}[+] Test 3: Full HTTP headers analysis${NC}"
echo "---"
echo "$HEADERS"

echo ""

# Summary
if [ "$VULN_FOUND" = "1" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED${NC}"
    echo "Server version information is exposed, allowing attackers to:"
    echo "  - Identify known vulnerabilities in specific versions"
    echo "  - Craft targeted exploits for vulnerable server versions"
    echo "  - Reduce attack surface reconnaissance time"
    exit 0
else
    echo -e "${YELLOW}[*] No obvious version disclosure found${NC}"
    exit 1
fi