#!/bin/bash

# POC: Missing Cache-Control Headers on Sensitive Pages
# This script demonstrates that sensitive pages lack Cache-Control headers
# allowing browser/proxy caching of sensitive financial data

TARGET_URL="${1:-http://localhost:5003}"
DEFAULT_USER="user"
DEFAULT_PASS="user"

echo "=========================================="
echo "Missing Cache-Control Headers Vulnerability"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Check if we can connect to the target
if ! curl -s -m 3 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[ERROR] Cannot connect to $TARGET_URL"
    exit 1
fi

# First, login to get authenticated session
echo "[*] Step 1: Authenticating with default credentials..."
echo "    Username: $DEFAULT_USER"
echo "    Password: $DEFAULT_PASS"
echo ""

LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -d "username=$DEFAULT_USER&password=$DEFAULT_PASS" \
    "$TARGET_URL/login" 2>&1)

# Check if login was successful by checking for Set-Cookie
if grep -q "session=" /tmp/cookies.txt 2>/dev/null; then
    echo "✓ Authentication successful"
    echo ""
else
    echo "⚠ Could not authenticate, testing unauthenticated access..."
    echo ""
fi

# Now test /transactions endpoint with authentication
echo "[*] Step 2: Checking /transactions for cache control headers..."
echo ""

TRANSACTIONS_RESPONSE=$(curl -s -i -b /tmp/cookies.txt "$TARGET_URL/transactions" 2>&1)

echo "Response Headers:"
echo "================="
echo "$TRANSACTIONS_RESPONSE" | head -20
echo ""

# Extract cache control headers
CACHE_CONTROL=$(echo "$TRANSACTIONS_RESPONSE" | grep -i '^cache-control:')
PRAGMA=$(echo "$TRANSACTIONS_RESPONSE" | grep -i '^pragma:')
EXPIRES=$(echo "$TRANSACTIONS_RESPONSE" | grep -i '^expires:')
HTTP_STATUS=$(echo "$TRANSACTIONS_RESPONSE" | head -1)

echo "Analysis:"
echo "=========="
echo "HTTP Status: $HTTP_STATUS"
echo ""

VULNERABLE=false

if [ -z "$CACHE_CONTROL" ]; then
    echo "❌ VULNERABLE: Cache-Control header is MISSING"
    VULNERABLE=true
else
    echo "✓ Cache-Control found: $CACHE_CONTROL"
fi

if [ -z "$PRAGMA" ]; then
    echo "❌ VULNERABLE: Pragma header is MISSING"
    VULNERABLE=true
else
    echo "✓ Pragma found: $PRAGMA"
fi

if [ -z "$EXPIRES" ]; then
    echo "❌ VULNERABLE: Expires header is MISSING"
    VULNERABLE=true
else
    echo "✓ Expires found: $EXPIRES"
fi

echo ""
echo "=========================================="
if [ "$VULNERABLE" = true ]; then
    echo "RESULT: ❌ VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo ""
    echo "Impact:"
    echo "- Sensitive transaction data can be cached by browsers"
    echo "- Data can be cached by proxy servers on corporate networks"
    echo "- Financial information may be accessible to other users"
    echo "- Cache can be retrieved from browser history or forensic tools"
    echo ""
    exit 0
else
    echo "RESULT: ✓ Cache headers properly configured"
    echo "=========================================="
    exit 1
fi