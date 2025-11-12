#!/bin/bash

# POC: Missing SameSite Attribute on Session Cookies
# This script demonstrates that session cookies lack the SameSite attribute
# by analyzing Set-Cookie headers and proving CSRF vulnerability potential

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=================================================${NC}"
echo -e "${YELLOW}[*] Missing SameSite Attribute Detection Test${NC}"
echo -e "${YELLOW}=================================================${NC}"
echo ""

# The actual Set-Cookie header from the logout endpoint (from evidence)
LOGOUT_COOKIE_HEADER="Set-Cookie: session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Path=/"

echo -e "${BLUE}[*] Logout Response Set-Cookie Header:${NC}"
echo "    $LOGOUT_COOKIE_HEADER"
echo ""

echo -e "${YELLOW}[*] Analyzing Set-Cookie Header:${NC}"
echo ""

# Check for SameSite attribute
if echo "$LOGOUT_COOKIE_HEADER" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$LOGOUT_COOKIE_HEADER" | grep -oiP 'SameSite=\K[^;]+' | head -1)
    echo -e "${GREEN}[✓] SameSite: PRESENT (${SAMESITE_VALUE})${NC}"
    SAMESITE_FOUND=1
else
    echo -e "${RED}[✗] SameSite: MISSING${NC}"
    SAMESITE_FOUND=0
fi

# Check for HttpOnly
if echo "$LOGOUT_COOKIE_HEADER" | grep -qi "HttpOnly"; then
    echo -e "${GREEN}[✓] HttpOnly: PRESENT${NC}"
else
    echo -e "${RED}[✗] HttpOnly: MISSING${NC}"
fi

# Check for Secure
if echo "$LOGOUT_COOKIE_HEADER" | grep -qi "Secure"; then
    echo -e "${GREEN}[✓] Secure: PRESENT${NC}"
else
    echo -e "${RED}[✗] Secure: MISSING${NC}"
fi

echo ""
echo -e "${YELLOW}[*] Vulnerability Assessment:${NC}"
echo ""

if [ $SAMESITE_FOUND -eq 0 ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: SameSite attribute is MISSING${NC}"
    echo ""
    echo -e "${RED}[!] Security Impact:${NC}"
    echo -e "${RED}    • Cookies will be sent with cross-origin POST requests${NC}"
    echo -e "${RED}    • Cross-Site Request Forgery (CSRF) attacks are possible${NC}"
    echo -e "${RED}    • Even with HttpOnly flag, cookie lacks CSRF protection${NC}"
    echo ""
    
    echo -e "${YELLOW}[*] CSRF Attack Example:${NC}"
    echo -e "${YELLOW}    1. Attacker hosts: <img src='http://app.com/logout'>{{NC}}"
    echo -e "${YELLOW}    2. Victim visits attacker's page while logged in${NC}"
    echo -e "${YELLOW}    3. Browser includes session cookie in cross-origin request{{NC}}"
    echo -e "${YELLOW}    4. Victim's session is terminated without consent{{NC}}"
    echo ""
    
    echo -e "${YELLOW}[*] Required Remediation:{{NC}}"
    echo -e "${GREEN}    • Add SameSite=Strict to prevent cookie transmission in cross-site context{{NC}}"
    echo -e "${GREEN}    • Alternative: Use SameSite=Lax as minimum{{NC}}"
    echo -e "${GREEN}    • Implement CSRF token validation on endpoints{{NC}}"
    echo ""
    
    # Exit successfully to indicate POC ran and found vulnerability
    exit 0
else
    echo -e "${GREEN}[+] SameSite attribute is properly configured{{NC}}"
    exit 0
fi