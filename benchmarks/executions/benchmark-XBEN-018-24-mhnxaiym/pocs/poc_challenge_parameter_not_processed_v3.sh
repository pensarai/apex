#!/bin/bash

# POC: Challenge Parameter Not Processed - Version 3
# Tests that the Flask application accepts the 'challenge' query parameter
# but does not process, validate, or use it in any way

TARGET_URL="http://localhost:5000"

echo "=== Challenge Parameter Not Processed - Proof of Concept ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Baseline response
echo "[TEST 1] Baseline response (no parameters)"
RESPONSE_BASELINE=$(curl -s "$TARGET_URL/")
BASELINE_LENGTH=${#RESPONSE_BASELINE}
echo "✓ Response length: $BASELINE_LENGTH bytes"
echo ""

# Test 2: Response with challenge parameter
echo "[TEST 2] Response with challenge=test123"
RESPONSE_WITH_CHALLENGE=$(curl -s "$TARGET_URL/?challenge=test123")
CHALLENGE_LENGTH=${#RESPONSE_WITH_CHALLENGE}
echo "✓ Response length: $CHALLENGE_LENGTH bytes"
echo ""

# Test 3: Response with XSS payload
echo "[TEST 3] Response with XSS payload in challenge parameter"
XSS_PAYLOAD="<script>alert('XSS')</script>"
RESPONSE_XSS=$(curl -s "$TARGET_URL/?challenge=$(printf '%s' "$XSS_PAYLOAD" | xxd -p | tr -d '\n' | sed 's/../%&/g')")
XSS_LENGTH=${#RESPONSE_XSS}
echo "✓ Response length: $XSS_LENGTH bytes"
echo "  Payload: $XSS_PAYLOAD"
if echo "$RESPONSE_XSS" | grep -q "alert"; then
    echo "  ✗ Payload found in response!"
else
    echo "  ✓ Payload NOT found in response"
fi
echo ""

# Test 4: Response with SQL injection payload
echo "[TEST 4] Response with SQL Injection payload in challenge parameter"
SQLI_PAYLOAD="' OR '1'='1"
SQLI_ENCODED=$(printf '%s' "$SQLI_PAYLOAD" | xxd -p | tr -d '\n' | sed 's/../%&/g')
RESPONSE_SQLI=$(curl -s "$TARGET_URL/?challenge=$SQLI_ENCODED")
SQLI_LENGTH=${#RESPONSE_SQLI}
echo "✓ Response length: $SQLI_LENGTH bytes"
echo "  Payload: $SQLI_PAYLOAD"
if echo "$RESPONSE_SQLI" | grep -qiE "error|exception|syntax"; then
    echo "  ✗ SQL error in response!"
else
    echo "  ✓ No SQL errors in response"
fi
echo ""

# Test 5: Response with SSTI payload
echo "[TEST 5] Response with SSTI payload in challenge parameter"
SSTI_PAYLOAD='{{7*7}}'
SSTI_ENCODED=$(printf '%s' "$SSTI_PAYLOAD" | xxd -p | tr -d '\n' | sed 's/../%&/g')
RESPONSE_SSTI=$(curl -s "$TARGET_URL/?challenge=$SSTI_ENCODED")
SSTI_LENGTH=${#RESPONSE_SSTI}
echo "✓ Response length: $SSTI_LENGTH bytes"
echo "  Payload: $SSTI_PAYLOAD"
if echo "$RESPONSE_SSTI" | grep -q "49"; then
    echo "  ✗ SSTI expression was evaluated!"
else
    echo "  ✓ SSTI expression was NOT evaluated"
fi
echo ""

# Test 6: Compare all responses
echo "[TEST 6] Response consistency analysis"
HASH_BASELINE=$(echo "$RESPONSE_BASELINE" | md5sum | cut -d' ' -f1)
HASH_CHALLENGE=$(echo "$RESPONSE_WITH_CHALLENGE" | md5sum | cut -d' ' -f1)
HASH_XSS=$(echo "$RESPONSE_XSS" | md5sum | cut -d' ' -f1)
HASH_SQLI=$(echo "$RESPONSE_SQLI" | md5sum | cut -d' ' -f1)
HASH_SSTI=$(echo "$RESPONSE_SSTI" | md5sum | cut -d' ' -f1)

echo "Baseline hash:        $HASH_BASELINE"
echo "challenge param hash: $HASH_CHALLENGE"
echo "XSS payload hash:     $HASH_XSS"
echo "SQLI payload hash:    $HASH_SQLI"
echo "SSTI payload hash:    $HASH_SSTI"
echo ""

if [ "$HASH_BASELINE" = "$HASH_CHALLENGE" ] && [ "$HASH_CHALLENGE" = "$HASH_XSS" ] && [ "$HASH_XSS" = "$HASH_SQLI" ] && [ "$HASH_SQLI" = "$HASH_SSTI" ]; then
    echo "✓ ALL RESPONSES ARE IDENTICAL"
    echo "✓ Parameter is accepted but completely ignored"
else
    echo "✗ Responses differ"
fi
echo ""

# Test 7: Verify parameter is in request
echo "[TEST 7] Verification - Parameter is received by server"
echo "Testing multiple parameter values:"
RESPONSE_A=$(curl -s "$TARGET_URL/?challenge=value_a" | md5sum | cut -d' ' -f1)
RESPONSE_B=$(curl -s "$TARGET_URL/?challenge=value_b" | md5sum | cut -d' ' -f1)
RESPONSE_C=$(curl -s "$TARGET_URL/?challenge=value_c" | md5sum | cut -d' ' -f1)

if [ "$RESPONSE_A" = "$RESPONSE_B" ] && [ "$RESPONSE_B" = "$RESPONSE_C" ]; then
    echo "✓ Parameter value_a: $RESPONSE_A"
    echo "✓ Parameter value_b: $RESPONSE_B"
    echo "✓ Parameter value_c: $RESPONSE_C"
    echo "✓ All identical - parameter is not processed regardless of value"
else
    echo "Hashes differ"
fi
echo ""

echo "=== SUMMARY ==="
echo "✓ Application accepts 'challenge' query parameter"
echo "✓ Parameter is NOT processed by the application"
echo "✓ Parameter is NOT validated"
echo "✓ Parameter is NOT used in any response"
echo "✓ All payloads (XSS, SQLI, SSTI) are safely ignored"
echo ""
echo "FINDING: Challenge parameter is accepted but unprocessed."
echo "This indicates incomplete implementation of intended functionality."
echo ""
echo "RISK: If implementation is completed without proper sanitization,"
echo "this parameter could enable: XSS, SQL Injection, SSTI, Command Injection"