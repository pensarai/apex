#!/bin/bash

# POC: Missing HSTS Header and HTTP-Only Operation
# Demonstrates vulnerability where application runs on HTTP without HTTPS support
# and fails to set Strict-Transport-Security header

TARGET="http://localhost:5001"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Testing for Missing HSTS Header and HTTP-Only Operation${NC}\n"

# Test 1: HTTP Connection
echo -e "${YELLOW}[Test 1] HTTP Connection on Port 5001${NC}"
HTTP_RESPONSE=$(curl -v "$TARGET" 2>&1)
if echo "$HTTP_RESPONSE" | grep -q "HTTP/1"; then
    HTTP_VERSION=$(echo "$HTTP_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $3}')
    echo -e "${GREEN}✓ HTTP connection successful${NC}"
    echo -e "  Protocol: $HTTP_VERSION"
    echo -e "  Status: $(echo "$HTTP_RESPONSE" | grep "< HTTP" | head -1)"
else
    echo -e "${RED}✗ Failed to connect to HTTP endpoint${NC}"
    exit 1
fi

# Test 2: Check for HSTS Header
echo -e "\n${YELLOW}[Test 2] HSTS Header Check${NC}"
HSTS_HEADER=$(echo "$HTTP_RESPONSE" | grep -i "strict-transport-security")
if [ -z "$HSTS_HEADER" ]; then
    echo -e "${RED}✗ HSTS Header NOT present${NC}"
    HSTS_VULNERABLE=1
else
    echo -e "${GREEN}✓ HSTS Header found: $HSTS_HEADER${NC}"
    HSTS_VULNERABLE=0
fi

# Test 3: Check for Other Security Headers
echo -e "\n${YELLOW}[Test 3] HTTP Response Headers${NC}"
echo "$HTTP_RESPONSE" | grep "< " | grep -E "Content-Type|Content-Length|Server|Date"

# Test 4: HTTPS Connection Test
echo -e "\n${YELLOW}[Test 4] HTTPS Connection Attempt (Port 443)${NC}"
HTTPS_TEST=$(curl -v https://localhost:5001 2>&1 | head -20)
if echo "$HTTPS_TEST" | grep -qE "Connection refused|refused|SSL.*certificate|self-signed"; then
    echo -e "${RED}✗ HTTPS not available or connection refused${NC}"
    echo -e "  (Expected: Application does not support HTTPS)"
fi

# Test 5: Verify HTTP/HTTPS Protocol Details
echo -e "\n${YELLOW}[Test 5] Protocol Analysis${NC}"
echo "$HTTP_RESPONSE" | grep -E "TLS|SSL|certificate" && echo "SSL/TLS detected" || echo -e "${RED}✗ No SSL/TLS encryption${NC}"

# Vulnerability Summary
echo -e "\n${YELLOW}[*] Vulnerability Summary${NC}"
if [ $HSTS_VULNERABLE -eq 1 ]; then
    echo -e "${RED}VULNERABLE: Missing HSTS Header${NC}"
    echo -e "  - Application does not enforce HTTPS"
    echo -e "  - No Strict-Transport-Security header present"
    echo -e "  - HTTP traffic is unencrypted and vulnerable to MITM attacks"
    echo -e "  - Browsers cannot be instructed to upgrade to HTTPS"
    exit 0
else
    echo -e "${GREEN}HSTS Header present - Vulnerability mitigated${NC}"
    exit 0
fi