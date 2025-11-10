#!/bin/bash

# POC: Missing Strict-Transport-Security (HSTS) Header
# This script demonstrates that the application does not implement HSTS protection

TARGET="http://localhost:5001"
ECHO_COLOR_RED='\033[0;31m'
ECHO_COLOR_GREEN='\033[0;32m'
ECHO_COLOR_YELLOW='\033[1;33m'
ECHO_COLOR_RESET='\033[0m'

echo "=========================================="
echo "POC: Missing HSTS Header Vulnerability"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test 1: Check for HSTS header on root endpoint
echo "[Test 1] Checking for Strict-Transport-Security header on /"
echo "Command: curl -I http://localhost:5001/"
echo ""

RESPONSE=$(curl -s -I http://localhost:5001/)
echo "$RESPONSE"
echo ""

if echo "$RESPONSE" | grep -qi "strict-transport-security"; then
    echo -e "${ECHO_COLOR_GREEN}[✓] HSTS header is present${ECHO_COLOR_RESET}"
    HSTS_VALUE=$(echo "$RESPONSE" | grep -i "strict-transport-security" | cut -d: -f2- | xargs)
    echo "    Value: $HSTS_VALUE"
else
    echo -e "${ECHO_COLOR_RED}[✗] VULNERABILITY CONFIRMED: HSTS header is missing${ECHO_COLOR_RESET}"
fi

echo ""
echo "---"
echo ""

# Test 2: Check multiple endpoints for HSTS
echo "[Test 2] Checking HSTS on multiple endpoints"
ENDPOINTS=("/" "/login" "/register" "/dashboard")
MISSING_COUNT=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "  Testing: $endpoint"
    HEADERS=$(curl -s -I "http://localhost:5001$endpoint" 2>&1)
    
    if echo "$HEADERS" | grep -qi "strict-transport-security"; then
        echo -e "    ${ECHO_COLOR_GREEN}[✓] HSTS present${ECHO_COLOR_RESET}"
    else
        echo -e "    ${ECHO_COLOR_RED}[✗] HSTS missing${ECHO_COLOR_RESET}"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "---"
echo ""

# Test 3: Demonstrate the security risk
echo "[Test 3] Security Risk Demonstration"
echo "  Without HSTS, the application is vulnerable to:"
echo "  1. Protocol Downgrade Attacks - Users can be forced to use HTTP"
echo "  2. SSL Stripping - MITM attackers can strip HTTPS"
echo "  3. Cookie Hijacking - Session cookies exposed over HTTP"
echo ""
echo "  Verifying HTTP accessibility:"

HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/)
if [ "$HTTP_RESPONSE" = "200" ]; then
    echo -e "    ${ECHO_COLOR_RED}[✗] Application is accessible over insecure HTTP (Status: $HTTP_RESPONSE)${ECHO_COLOR_RESET}"
    echo "    This confirms users can be downgraded to unencrypted connections"
else
    echo -e "    ${ECHO_COLOR_GREEN}[✓] HTTP access blocked (Status: $HTTP_RESPONSE)${ECHO_COLOR_RESET}"
fi

echo ""
echo "---"
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""

if [ $MISSING_COUNT -eq ${#ENDPOINTS[@]} ]; then
    echo -e "${ECHO_COLOR_RED}VULNERABILITY CONFIRMED:${ECHO_COLOR_RESET}"
    echo "  • HSTS header is missing on ALL tested endpoints ($MISSING_COUNT/${#ENDPOINTS[@]})"
    echo "  • No browser-level HTTPS enforcement"
    echo "  • Users vulnerable to protocol downgrade attacks"
    echo "  • No protection against SSL stripping"
    echo "  • Session cookies can be hijacked over HTTP"
    echo ""
    echo -e "${ECHO_COLOR_YELLOW}Recommendation:${ECHO_COLOR_RESET}"
    echo "  Implement HSTS header with: max-age=31536000; includeSubDomains; preload"
    echo ""
    exit 0  # Success - vulnerability confirmed
else
    echo -e "${ECHO_COLOR_GREEN}HSTS header is properly configured${ECHO_COLOR_RESET}"
    echo ""
    exit 1  # No vulnerability found
fi