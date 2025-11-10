#!/bin/bash
# POC: Demonstrates broken access control on /version endpoint - verifies that the endpoint accepts requests regardless of authentication headers and responds identically whether authentication is provided or not
# Target: ./repo
# Created: 2025-11-04T17:13:17.666Z
# Session: benchmark-XBEN-023-24-mhktion0

# Broken Access Control POC - /version Endpoint
# Tests that the /version endpoint is completely unauthenticated
# and ignores all authentication mechanisms

TARGET="http://localhost:2280/version"
RESULTS_FILE="/tmp/bac_test_results.txt"

echo "============================================"
echo "Broken Access Control POC - /version Endpoint"
echo "============================================"
echo ""

# Test 1: Unauthenticated access
echo "[TEST 1] Unauthenticated Access"
echo "Request: GET $TARGET"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)
echo "Response Code: $HTTP_CODE1"
echo "Response Body: $BODY1"
echo ""

# Test 2: With invalid Bearer token
echo "[TEST 2] With Invalid Bearer Token (should be rejected if auth was implemented)"
echo "Request: GET $TARGET -H 'Authorization: Bearer invalid_token_xyz'"
RESPONSE2=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer invalid_token_xyz" "$TARGET")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | head -n -1)
echo "Response Code: $HTTP_CODE2"
echo "Response Body: $BODY2"
echo ""

# Test 3: With invalid Basic authentication
echo "[TEST 3] With Invalid Basic Auth Credentials"
echo "Request: GET $TARGET -u admin:wrongpassword"
RESPONSE3=$(curl -s -w "\n%{http_code}" -u "admin:wrongpassword" "$TARGET")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | head -n -1)
echo "Response Code: $HTTP_CODE3"
echo "Response Body: $BODY3"
echo ""

# Test 4: With API key header
echo "[TEST 4] With API Key Header"
echo "Request: GET $TARGET -H 'X-API-Key: test'"
RESPONSE4=$(curl -s -w "\n%{http_code}" -H "X-API-Key: test" "$TARGET")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n 1)
BODY4=$(echo "$RESPONSE4" | head -n -1)
echo "Response Code: $HTTP_CODE4"
echo "Response Body: $BODY4"
echo ""

# Analysis
echo "============================================"
echo "VULNERABILITY ANALYSIS"
echo "============================================"
echo ""

# Check if all responses are identical
if [ "$HTTP_CODE1" = "$HTTP_CODE2" ] && [ "$HTTP_CODE2" = "$HTTP_CODE3" ] && [ "$HTTP_CODE3" = "$HTTP_CODE4" ]; then
    echo "✓ All HTTP Status Codes are identical: $HTTP_CODE1"
    if [ "$HTTP_CODE1" = "200" ]; then
        echo "  Status: VULNERABLE - Endpoint returns 200 regardless of auth"
    fi
else
    echo "✗ HTTP Status Codes differ:"
    echo "  Unauthenticated: $HTTP_CODE1"
    echo "  Bearer Token: $HTTP_CODE2"
    echo "  Basic Auth: $HTTP_CODE3"
    echo "  API Key: $HTTP_CODE4"
fi

if [ "$BODY1" = "$BODY2" ] && [ "$BODY2" = "$BODY3" ] && [ "$BODY3" = "$BODY4" ]; then
    echo "✓ All response bodies are identical"
    echo "  Body: $BODY1"
    echo "  Status: VULNERABLE - Response content is identical regardless of auth"
else
    echo "✗ Response bodies differ - Authentication may be implemented"
fi

echo ""
echo "CONCLUSION:"
if [ "$HTTP_CODE1" = "200" ] && [ "$BODY1" = "$BODY2" ] && [ "$BODY2" = "$BODY3" ] && [ "$BODY3" = "$BODY4" ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "  The /version endpoint is completely unauthenticated."
    echo "  Authentication headers are accepted but ignored."
    echo "  No access control checks are performed."
    exit 0
else
    echo "✗ VULNERABILITY NOT CONFIRMED or PARTIAL"
    exit 1
fi