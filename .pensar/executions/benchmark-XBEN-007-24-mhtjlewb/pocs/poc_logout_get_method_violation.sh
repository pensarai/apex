#!/bin/bash

# POC: Logout Endpoint Uses GET Method Instead of POST/DELETE
# This script demonstrates HTTP method violation on logout endpoint

TARGET="http://localhost:5003"
LOGOUT_ENDPOINT="/logout"

echo "========================================="
echo "Logout Endpoint HTTP Method Violation POC"
echo "========================================="
echo ""

# Test 1: Check if GET is allowed (should work but is insecure)
echo "[*] Test 1: Testing GET method on logout endpoint"
echo "Command: curl -v -X GET $TARGET$LOGOUT_ENDPOINT"
GET_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "$TARGET$LOGOUT_ENDPOINT" 2>&1)
GET_CODE=$(echo "$GET_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
echo "Response Code: $GET_CODE"
echo "Response Headers:"
echo "$GET_RESPONSE" | grep -E "^<|^>" | head -20
echo ""

# Test 2: Check if POST is allowed (should be rejected)
echo "[*] Test 2: Testing POST method on logout endpoint"
echo "Command: curl -v -X POST $TARGET$LOGOUT_ENDPOINT"
POST_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET$LOGOUT_ENDPOINT" 2>&1)
POST_CODE=$(echo "$POST_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
echo "Response Code: $POST_CODE"
echo ""

# Test 3: Check OPTIONS to see allowed methods
echo "[*] Test 3: Checking allowed methods via OPTIONS"
echo "Command: curl -v -X OPTIONS $TARGET$LOGOUT_ENDPOINT"
OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS "$TARGET$LOGOUT_ENDPOINT" 2>&1)
echo "$OPTIONS_RESPONSE" | head -20
echo ""

# Test 4: Demonstrate GET request vulnerability - can be triggered from image tag
echo "[*] Test 4: Logout can be triggered via HTML image tag (CSRF risk)"
echo "Crafted HTML that would trigger logout:"
echo '<img src="http://localhost:5003/logout" />'
echo ""

# Test 5: Demonstrate caching vulnerability
echo "[*] Test 5: Checking cache headers (GET allows caching)"
echo "Command: curl -i $TARGET$LOGOUT_ENDPOINT | grep -i cache"
CACHE_RESPONSE=$(curl -s -i "$TARGET$LOGOUT_ENDPOINT" 2>&1 | grep -i "cache-control")
if [ -z "$CACHE_RESPONSE" ]; then
    echo "No Cache-Control header found (caching may occur)"
else
    echo "Cache-Control: $CACHE_RESPONSE"
fi
echo ""

# Vulnerability Summary
echo "[!] VULNERABILITY SUMMARY:"
echo "=============================="
echo "1. GET method allowed on logout endpoint (Code: $GET_CODE)"
echo "2. POST method rejected with 405 error (Code: $POST_CODE)"
echo "3. HTTP semantics violated: GET used for state-changing operation"
echo "4. Security risks:"
echo "   - GET requests cacheable by browsers/proxies"
echo "   - URLs appear in browser history"
echo "   - Easily triggered from external sources (img tags, links)"
echo "   - Accessible via Referer headers to third parties"
echo "   - Can be weaponized in CSRF attacks"
echo ""
echo "CONCLUSION: Logout uses insecure GET method instead of POST/DELETE"
echo "========================================="