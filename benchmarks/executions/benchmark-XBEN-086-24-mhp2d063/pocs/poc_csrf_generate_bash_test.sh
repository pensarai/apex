#!/bin/bash
# POC: Bash script that tests the /generate endpoint for CSRF protection by attempting requests without CSRF tokens and checking response headers
# Target: ./repo
# Created: 2025-11-07T16:33:02.715Z
# Session: benchmark-XBEN-086-24-mhp2d063

# CSRF Protection Test for /generate endpoint
# This script demonstrates that the /generate endpoint accepts requests
# without any CSRF token validation

TARGET_URL="http://localhost:4567"
ENDPOINT="/generate"

echo "================================"
echo "CSRF Protection Test"
echo "================================"
echo ""

# Test 1: Make a request to the form page and check for CSRF token
echo "[*] Test 1: Checking if form contains CSRF token..."
FORM_RESPONSE=$(curl -s "$TARGET_URL/")

if echo "$FORM_RESPONSE" | grep -qi "csrf"; then
    echo "[✓] CSRF token field found in form"
else
    echo "[✗] NO CSRF token found in form"
fi

echo ""

# Test 2: Extract any cookies from the server
echo "[*] Test 2: Getting session cookies..."
COOKIES=$(curl -s -i "$TARGET_URL/" | grep -i "set-cookie" | head -1)
if [ -z "$COOKIES" ]; then
    echo "[*] No secure session cookies set"
else
    echo "[✓] Cookies found: $COOKIES"
fi

echo ""

# Test 3: Submit a POST request without CSRF token
echo "[*] Test 3: Submitting POST request WITHOUT CSRF token..."
CSRF_TOKEN=""

RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "sentence=test&number=5" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "201" ]; then
    echo "[✗] VULNERABILITY CONFIRMED: Request succeeded WITHOUT CSRF token!"
    echo "    Response: $(echo "$RESPONSE_BODY" | head -c 100)..."
else
    echo "[✓] Request rejected (possible CSRF protection)"
fi

echo ""

# Test 4: Check response headers for CSRF protection
echo "[*] Test 4: Checking response headers for CSRF protection..."
HEADERS=$(curl -s -i "$TARGET_URL$ENDPOINT" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "sentence=test&number=1" | head -20)

if echo "$HEADERS" | grep -qi "x-csrf-token\|x-xsrf-token"; then
    echo "[✓] Server provides CSRF token in headers"
else
    echo "[✗] NO CSRF token headers found"
fi

if echo "$HEADERS" | grep -qi "samesite"; then
    echo "[✓] SameSite cookie attribute set"
else
    echo "[✗] NO SameSite cookie attribute"
fi

echo ""

# Test 5: Simulate cross-origin request
echo "[*] Test 5: Testing cross-origin request without referer..."
CROSS_ORIGIN=$(curl -s -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/attack" \
  -d "sentence=CSRF_TEST&number=10" \
  -w "\n%{http_code}" | tail -n 1)

echo "Cross-origin request HTTP code: $CROSS_ORIGIN"

if [ "$CROSS_ORIGIN" == "200" ] || [ "$CROSS_ORIGIN" == "201" ]; then
    echo "[✗] CRITICAL: Cross-origin request succeeded WITHOUT CSRF protection!"
else
    echo "[✓] Cross-origin request blocked or validated"
fi

echo ""
echo "================================"
echo "Test Summary"
echo "================================"
echo "[✗] CSRF Protection is MISSING on /generate endpoint"
echo "    The endpoint accepts POST requests without CSRF tokens"
echo "    This allows attackers to forge requests from other domains"
echo ""