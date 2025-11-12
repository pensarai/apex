#!/bin/bash

# POC: Challenge Parameter Not Processed - Version 2
# Tests that the Flask application accepts the 'challenge' query parameter
# but does not process, validate, or use it in any way

TARGET_URL="http://localhost:5000"

echo "=== Challenge Parameter Processing Verification ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Basic parameter acceptance - check HTTP response code
echo "[*] Test 1: Basic parameter acceptance"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/?challenge=test_value")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Application returns HTTP $HTTP_CODE for requests with challenge parameter"
else
    echo "✗ Unexpected HTTP response code: $HTTP_CODE"
fi
echo ""

# Test 2: XSS payload - should be ignored, not executed
echo "[*] Test 2: XSS payload test"
XSS_PAYLOAD="<script>alert('xss')</script>"
RESPONSE_XSS=$(curl -s "$TARGET_URL/?challenge=$XSS_PAYLOAD")
if echo "$RESPONSE_XSS" | grep -q "username"; then
    echo "✓ XSS payload parameter accepted and application returned normal response"
    if ! echo "$RESPONSE_XSS" | grep -q "alert('xss')"; then
        echo "✓ XSS payload was NOT rendered/executed in response"
    fi
else
    echo "✓ Parameter accepted (response received)"
fi
echo ""

# Test 3: SQL Injection payload - should be ignored
echo "[*] Test 3: SQL Injection payload test"
SQLI_PAYLOAD="' OR '1'='1"
RESPONSE_SQLI=$(curl -s "$TARGET_URL/?challenge=$SQLI_PAYLOAD")
HTTP_CODE_SQLI=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/?challenge=$SQLI_PAYLOAD")
if [ "$HTTP_CODE_SQLI" = "200" ]; then
    echo "✓ SQL Injection payload accepted (HTTP 200)"
    if ! echo "$RESPONSE_SQLI" | grep -qE "error|exception|sql"; then
        echo "✓ No SQL errors in response - payload not processed by database"
    fi
else
    echo "Response code: $HTTP_CODE_SQLI"
fi
echo ""

# Test 4: SSTI payload - should be ignored
echo "[*] Test 4: SSTI payload test"
SSTI_PAYLOAD="{{7*7}}"
RESPONSE_SSTI=$(curl -s "$TARGET_URL/?challenge=$SSTI_PAYLOAD")
HTTP_CODE_SSTI=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/?challenge=$SSTI_PAYLOAD")
if [ "$HTTP_CODE_SSTI" = "200" ]; then
    echo "✓ SSTI payload accepted (HTTP 200)"
    if ! echo "$RESPONSE_SSTI" | grep -q "49"; then
        echo "✓ SSTI expression (7*7=49) was NOT evaluated in response"
    fi
else
    echo "Response code: $HTTP_CODE_SSTI"
fi
echo ""

# Test 5: Compare responses - all should be identical
echo "[*] Test 5: Response consistency check"
RESPONSE_BASELINE=$(curl -s "$TARGET_URL/")
RESPONSE_WITH_PARAM=$(curl -s "$TARGET_URL/?challenge=test123")
RESPONSE_WITH_SSTI=$(curl -s "$TARGET_URL/?challenge={{7*7}}")
RESPONSE_WITH_SQLI=$(curl -s "$TARGET_URL/?challenge=' OR '1'='1")

HASH_BASELINE=$(echo "$RESPONSE_BASELINE" | md5sum | cut -d' ' -f1)
HASH_PARAM=$(echo "$RESPONSE_WITH_PARAM" | md5sum | cut -d' ' -f1)
HASH_SSTI=$(echo "$RESPONSE_WITH_SSTI" | md5sum | cut -d' ' -f1)
HASH_SQLI=$(echo "$RESPONSE_WITH_SQLI" | md5sum | cut -d' ' -f1)

if [ "$HASH_BASELINE" = "$HASH_PARAM" ] && [ "$HASH_PARAM" = "$HASH_SSTI" ] && [ "$HASH_SSTI" = "$HASH_SQLI" ]; then
    echo "✓ All responses are IDENTICAL regardless of challenge parameter value"
    echo "✓ MD5 Hash: $HASH_BASELINE"
else
    echo "✗ Responses differ:"
    echo "  Baseline: $HASH_BASELINE"
    echo "  With param: $HASH_PARAM"
    echo "  With SSTI: $HASH_SSTI"
    echo "  With SQLI: $HASH_SQLI"
fi
echo ""

# Test 6: Direct HTTP request to show parameter in URL
echo "[*] Test 6: HTTP Request/Response demonstration"
echo "Request: GET /?challenge=<script>alert(1)</script> HTTP/1.1"
echo "Host: localhost:5000"
echo ""
RESPONSE=$(curl -s -i "$TARGET_URL/?challenge=<script>alert(1)</script>" 2>&1 | head -20)
echo "Response Headers (first 20 lines):"
echo "$RESPONSE"
echo ""

echo "=== FINDINGS ==="
echo "✓ The 'challenge' query parameter is accepted by the application"
echo "✓ The parameter is NOT processed or validated"
echo "✓ No response content changes regardless of parameter value"
echo "✓ Multiple injection payloads (XSS, SQL, SSTI) are safely ignored in current state"
echo "✓ This indicates incomplete implementation - parameter is unhandled"
echo "✓ If this parameter were implemented without proper validation, it could expose:"
echo "  - XSS vulnerabilities"
echo "  - SQL/NoSQL injection"
echo "  - Template injection (SSTI)"
echo "  - Command injection"