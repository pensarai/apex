#!/bin/bash
# POC: Demonstrates improper input type validation vulnerability where non-string values (null, integer, boolean) cause HTTP 500 errors instead of graceful error handling
# Target: ./repo
# Created: 2025-11-07T17:25:42.973Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# POC for Improper Input Type Validation Leading to Information Disclosure
# Tests the /check_service endpoint with non-string JSON values
# Expected: 400 Bad Request with proper error message
# Actual: 500 Internal Server Error (type validation missing)

TARGET_URL="http://127.0.0.1:80/check_service"

echo "======================================"
echo "Improper Input Type Validation POC"
echo "======================================"
echo ""

# Test 1: Null value
echo "[*] Test 1: Sending null value in service_name"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":null}'"
echo ""
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":null}')

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "Response HTTP Code: $HTTP_CODE1"
echo "Response Body: $BODY1"
echo ""

# Test 2: Integer value
echo "[*] Test 2: Sending integer value in service_name"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":0}'"
echo ""
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":0}')

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "Response HTTP Code: $HTTP_CODE2"
echo "Response Body: $BODY2"
echo ""

# Test 3: Boolean value (true)
echo "[*] Test 3: Sending boolean value (true) in service_name"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":true}'"
echo ""
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":true}')

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "Response HTTP Code: $HTTP_CODE3"
echo "Response Body: $BODY3"
echo ""

# Test 4: Boolean value (false)
echo "[*] Test 4: Sending boolean value (false) in service_name"
echo "Command: curl -X POST $TARGET_URL -H 'Content-Type: application/json' -d '{\"service_name\":false}'"
echo ""
RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":false}')

HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

echo "Response HTTP Code: $HTTP_CODE4"
echo "Response Body: $BODY4"
echo ""

# Analysis
echo "======================================"
echo "ANALYSIS"
echo "======================================"
echo ""

if [ "$HTTP_CODE1" = "500" ] || [ "$HTTP_CODE2" = "500" ] || [ "$HTTP_CODE3" = "500" ] || [ "$HTTP_CODE4" = "500" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Type validation is missing"
    echo "[!] Non-string values cause HTTP 500 errors instead of graceful error handling"
    echo "[!] This indicates the application fails to validate input types before processing"
    echo ""
    echo "Expected Behavior: HTTP 400 with error message like 'Invalid service name: must be string'"
    echo "Actual Behavior: HTTP 500 with 'Internal Server Error'"
    echo ""
    echo "Vulnerable test cases:"
    [ "$HTTP_CODE1" = "500" ] && echo "  - null value: HTTP $HTTP_CODE1"
    [ "$HTTP_CODE2" = "500" ] && echo "  - integer value: HTTP $HTTP_CODE2"
    [ "$HTTP_CODE3" = "500" ] && echo "  - boolean true: HTTP $HTTP_CODE3"
    [ "$HTTP_CODE4" = "500" ] && echo "  - boolean false: HTTP $HTTP_CODE4"
else
    echo "[*] Type validation appears to be in place (no 500 errors detected)"
    echo "HTTP Codes received: $HTTP_CODE1, $HTTP_CODE2, $HTTP_CODE3, $HTTP_CODE4"
fi