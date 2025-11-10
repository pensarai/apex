#!/bin/bash

# POC: Dangerous HTTP Methods Enabled (PUT, DELETE, PATCH)
# Tests whether Apache server accepts dangerous HTTP methods

TARGET_URL="${1:-http://localhost:80}"
VERBOSE="${2:-true}"

echo "=========================================="
echo "Testing Dangerous HTTP Methods"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test PUT method
echo "[*] Testing PUT method..."
PUT_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$TARGET_URL" -d "test data")
PUT_STATUS=$(echo "$PUT_RESPONSE" | tail -n1)
PUT_BODY=$(echo "$PUT_RESPONSE" | sed '$d')

echo "Status Code: $PUT_STATUS"
if [ "$VERBOSE" = "true" ]; then
    echo "Response Body: $PUT_BODY"
fi
echo ""

# Test DELETE method
echo "[*] Testing DELETE method..."
DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET_URL")
DELETE_STATUS=$(echo "$DELETE_RESPONSE" | tail -n1)
DELETE_BODY=$(echo "$DELETE_RESPONSE" | sed '$d')

echo "Status Code: $DELETE_STATUS"
if [ "$VERBOSE" = "true" ]; then
    echo "Response Body: $DELETE_BODY"
fi
echo ""

# Test PATCH method
echo "[*] Testing PATCH method..."
PATCH_RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH "$TARGET_URL" -d "patch data")
PATCH_STATUS=$(echo "$PATCH_RESPONSE" | tail -n1)
PATCH_BODY=$(echo "$PATCH_RESPONSE" | sed '$d')

echo "Status Code: $PATCH_STATUS"
if [ "$VERBOSE" = "true" ]; then
    echo "Response Body: $PATCH_BODY"
fi
echo ""

# Analysis
echo "=========================================="
echo "Analysis:"
echo "=========================================="

VULNERABLE=0

if [ "$PUT_STATUS" = "200" ]; then
    echo "⚠️  PUT method accepted (HTTP $PUT_STATUS) - VULNERABILITY DETECTED"
    VULNERABLE=1
elif [ "$PUT_STATUS" = "405" ] || [ "$PUT_STATUS" = "403" ]; then
    echo "✓ PUT method properly rejected (HTTP $PUT_STATUS)"
else
    echo "? PUT method returned unexpected status (HTTP $PUT_STATUS)"
fi

if [ "$DELETE_STATUS" = "200" ]; then
    echo "⚠️  DELETE method accepted (HTTP $DELETE_STATUS) - VULNERABILITY DETECTED"
    VULNERABLE=1
elif [ "$DELETE_STATUS" = "405" ] || [ "$DELETE_STATUS" = "403" ]; then
    echo "✓ DELETE method properly rejected (HTTP $DELETE_STATUS)"
else
    echo "? DELETE method returned unexpected status (HTTP $DELETE_STATUS)"
fi

if [ "$PATCH_STATUS" = "200" ]; then
    echo "⚠️  PATCH method accepted (HTTP $PATCH_STATUS) - VULNERABILITY DETECTED"
    VULNERABLE=1
elif [ "$PATCH_STATUS" = "405" ] || [ "$PATCH_STATUS" = "403" ]; then
    echo "✓ PATCH method properly rejected (HTTP $PATCH_STATUS)"
else
    echo "? PATCH method returned unexpected status (HTTP $PATCH_STATUS)"
fi

echo ""
if [ $VULNERABLE -eq 1 ]; then
    echo "⚠️  RESULT: Dangerous HTTP methods are ENABLED on this server"
    exit 0
else
    echo "✓ RESULT: Server properly restricts dangerous HTTP methods"
    exit 1
fi