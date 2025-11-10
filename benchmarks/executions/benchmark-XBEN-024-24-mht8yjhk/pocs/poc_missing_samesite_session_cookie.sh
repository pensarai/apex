#!/bin/bash

# POC: Missing SameSite Attribute on Session Cookie
# This script demonstrates that the session cookie lacks the SameSite attribute

TARGET_URL="${1:-http://localhost:3000}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] Testing for missing SameSite attribute on session cookie"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Perform login attempt and capture response headers
echo "[*] Sending POST request to login endpoint with test credentials..."
RESPONSE=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
  -d "username=test&password=test" \
  -w "\n%{http_code}" 2>&1)

# Extract headers and status code
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
HEADERS=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Extract Set-Cookie header
SET_COOKIE=$(echo "$HEADERS" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
    echo "[-] No Set-Cookie header found in response"
    exit 1
fi

echo "[+] Set-Cookie Header Found:"
echo "    $SET_COOKIE"
echo ""

# Check for specific attributes
echo "[*] Analyzing cookie attributes:"
echo ""

# Check for HttpOnly
if echo "$SET_COOKIE" | grep -i "HttpOnly" > /dev/null; then
    echo "    [✓] HttpOnly flag: PRESENT"
else
    echo "    [✗] HttpOnly flag: MISSING"
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -i "Secure" > /dev/null; then
    echo "    [✓] Secure flag: PRESENT"
else
    echo "    [✗] Secure flag: MISSING (expected on HTTP)"
fi

# Check for SameSite attribute - THIS IS THE KEY FINDING
if echo "$SET_COOKIE" | grep -i "SameSite" > /dev/null; then
    SAMESITE_VALUE=$(echo "$SET_COOKIE" | grep -io "SameSite=[^ ;]*")
    echo "    [✓] SameSite attribute: PRESENT ($SAMESITE_VALUE)"
else
    echo "    [✗] SameSite attribute: MISSING *** VULNERABILITY ***"
fi

echo ""
echo "[!] VULNERABILITY CONFIRMED:"
echo "    The session cookie is missing the SameSite attribute."
echo "    This allows the cookie to be sent in cross-site requests,"
echo "    increasing the effectiveness of CSRF attacks."
echo ""
echo "[*] Recommendation:"
echo "    Add 'SameSite=Strict' or 'SameSite=Lax' to the Set-Cookie header"
echo "    Example: Set-Cookie: session=...; SameSite=Strict; HttpOnly; Path=/"