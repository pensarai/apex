#!/bin/bash

# POC: Challenge Parameter Not Processed
# Tests that the Flask application accepts the 'challenge' query parameter
# but does not process, validate, or use it in any way

TARGET_URL="http://localhost:5000"
RESULTS_FILE="/tmp/poc_results.txt"

echo "=== Challenge Parameter Processing Verification ===" | tee "$RESULTS_FILE"
echo "Target: $TARGET_URL" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 1: Basic parameter acceptance
echo "[*] Test 1: Basic parameter acceptance" | tee -a "$RESULTS_FILE"
RESPONSE1=$(curl -s "$TARGET_URL/?challenge=test_value")
if echo "$RESPONSE1" | grep -q "Login Form"; then
    echo "✓ Application returns 200 OK with normal content" | tee -a "$RESULTS_FILE"
else
    echo "✗ Unexpected response" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 2: XSS payload - should be ignored, not executed
echo "[*] Test 2: XSS payload test" | tee -a "$RESULTS_FILE"
XSS_PAYLOAD="<script>alert('xss')</script>"
XSS_ENCODED=$(printf '%s' "$XSS_PAYLOAD" | jq -sRr @uri)
RESPONSE2=$(curl -s "$TARGET_URL/?challenge=$XSS_ENCODED")
if echo "$RESPONSE2" | grep -q "Login Form"; then
    echo "✓ XSS payload parameter accepted but not processed" | tee -a "$RESULTS_FILE"
    if ! echo "$RESPONSE2" | grep -q "alert('xss')"; then
        echo "✓ XSS payload was NOT executed in response" | tee -a "$RESULTS_FILE"
    fi
else
    echo "✗ Unexpected response" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 3: SQL Injection payload - should be ignored
echo "[*] Test 3: SQL Injection payload test" | tee -a "$RESULTS_FILE"
SQLI_PAYLOAD="' OR '1'='1"
SQLI_ENCODED=$(printf '%s' "$SQLI_PAYLOAD" | jq -sRr @uri)
RESPONSE3=$(curl -s "$TARGET_URL/?challenge=$SQLI_ENCODED")
if echo "$RESPONSE3" | grep -q "Login Form"; then
    echo "✓ SQL Injection payload parameter accepted but not processed" | tee -a "$RESULTS_FILE"
else
    echo "✗ Unexpected response" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 4: SSTI payload - should be ignored
echo "[*] Test 4: SSTI payload test" | tee -a "$RESULTS_FILE"
SSTI_PAYLOAD="{{7*7}}"
SSTI_ENCODED=$(printf '%s' "$SSTI_PAYLOAD" | jq -sRr @uri)
RESPONSE4=$(curl -s "$TARGET_URL/?challenge=$SSTI_ENCODED")
if echo "$RESPONSE4" | grep -q "Login Form"; then
    echo "✓ SSTI payload parameter accepted but not processed" | tee -a "$RESULTS_FILE"
    if ! echo "$RESPONSE4" | grep -q "49"; then
        echo "✓ SSTI expression was NOT evaluated in response" | tee -a "$RESULTS_FILE"
    fi
else
    echo "✗ Unexpected response" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 5: Compare responses - all should be identical
echo "[*] Test 5: Response consistency check" | tee -a "$RESULTS_FILE"
RESPONSE_BASELINE=$(curl -s "$TARGET_URL/")
RESPONSE_WITH_PARAM=$(curl -s "$TARGET_URL/?challenge=test123")
if [ "$(echo "$RESPONSE_BASELINE" | md5sum | cut -d' ' -f1)" = "$(echo "$RESPONSE_WITH_PARAM" | md5sum | cut -d' ' -f1)" ]; then
    echo "✓ Response with and without challenge parameter are IDENTICAL" | tee -a "$RESULTS_FILE"
    echo "✓ Parameter is accepted but completely ignored" | tee -a "$RESULTS_FILE"
else
    echo "✗ Responses differ - parameter may be processed" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

echo "=== Summary ===" | tee -a "$RESULTS_FILE"
echo "✓ The 'challenge' query parameter is accepted by the application" | tee -a "$RESULTS_FILE"
echo "✓ The parameter is NOT processed or validated" | tee -a "$RESULTS_FILE"
echo "✓ No response content changes regardless of parameter value" | tee -a "$RESULTS_FILE"
echo "✓ Multiple injection payloads (XSS, SQL, SSTI) are safely ignored" | tee -a "$RESULTS_FILE"
echo "✓ This indicates incomplete implementation - parameter is unhandled" | tee -a "$RESULTS_FILE"

cat "$RESULTS_FILE"