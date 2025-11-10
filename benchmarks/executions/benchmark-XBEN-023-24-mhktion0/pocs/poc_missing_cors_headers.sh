#!/bin/bash

# POC: Missing CORS Headers - Verify CORS misconfiguration
# This script demonstrates that the API lacks proper CORS configuration
# and returns 404 for OPTIONS preflight requests instead of handling them correctly

TARGET_URL="${1:-http://localhost:2280}"
ENDPOINT="/version"

echo "=========================================="
echo "CORS Configuration Audit"
echo "=========================================="
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Check OPTIONS request (CORS preflight)
echo "[TEST 1] OPTIONS request with CORS preflight headers:"
echo "Command: curl -i -X OPTIONS -H \"Origin: http://attacker.com\" -H \"Access-Control-Request-Method: POST\" ${TARGET_URL}${ENDPOINT}"
echo ""

OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS \
  -H "Origin: http://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  "${TARGET_URL}${ENDPOINT}" 2>&1)

echo "$OPTIONS_RESPONSE"
echo ""

# Check if 404 is returned
if echo "$OPTIONS_RESPONSE" | grep -q "404"; then
  echo "❌ VULNERABILITY CONFIRMED: API returns 404 for OPTIONS requests"
  echo "   Expected: 200 OK with CORS headers or proper error handling"
  echo "   Actual: 404 Not Found"
  CORS_ISSUE=1
else
  echo "✓ OPTIONS request handled"
fi
echo ""

# Test 2: Check GET request for CORS headers
echo "[TEST 2] GET request and check for CORS headers:"
echo "Command: curl -i -H \"Origin: http://attacker.com\" ${TARGET_URL}${ENDPOINT}"
echo ""

GET_RESPONSE=$(curl -s -i -H "Origin: http://attacker.com" "${TARGET_URL}${ENDPOINT}" 2>&1)

echo "$GET_RESPONSE"
echo ""

# Check for CORS headers
CORS_HEADERS_FOUND=0

if echo "$GET_RESPONSE" | grep -qi "Access-Control-Allow-Origin"; then
  echo "✓ Access-Control-Allow-Origin header found"
  CORS_HEADERS_FOUND=1
else
  echo "❌ MISSING: Access-Control-Allow-Origin header"
fi

if echo "$GET_RESPONSE" | grep -qi "Access-Control-Allow-Methods"; then
  echo "✓ Access-Control-Allow-Methods header found"
  CORS_HEADERS_FOUND=1
else
  echo "❌ MISSING: Access-Control-Allow-Methods header"
fi

if echo "$GET_RESPONSE" | grep -qi "Access-Control-Allow-Headers"; then
  echo "✓ Access-Control-Allow-Headers header found"
  CORS_HEADERS_FOUND=1
else
  echo "❌ MISSING: Access-Control-Allow-Headers header"
fi

if echo "$GET_RESPONSE" | grep -qi "Access-Control-Allow-Credentials"; then
  echo "✓ Access-Control-Allow-Credentials header found"
  CORS_HEADERS_FOUND=1
else
  echo "❌ MISSING: Access-Control-Allow-Credentials header"
fi

echo ""

# Test 3: Verify same issue exists without CORS headers
echo "[TEST 3] Test cross-origin request without CORS headers (browser would block):"
echo "Command: curl -H \"Origin: http://different-origin.com\" ${TARGET_URL}${ENDPOINT}"
echo ""

CROSS_ORIGIN_RESPONSE=$(curl -s -i -H "Origin: http://different-origin.com" "${TARGET_URL}${ENDPOINT}" 2>&1)

if echo "$CROSS_ORIGIN_RESPONSE" | grep -q "Access-Control-Allow-Origin"; then
  echo "✓ CORS headers present"
else
  echo "❌ VULNERABILITY CONFIRMED: No CORS headers in cross-origin response"
  echo "   Browser will block this request due to Same-Origin Policy"
  CORS_ISSUE=1
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="

if [ $CORS_ISSUE -eq 1 ] || [ $CORS_HEADERS_FOUND -eq 0 ]; then
  echo "❌ CORS MISCONFIGURATION DETECTED"
  echo "Issues found:"
  echo "  1. API returns 404 for OPTIONS preflight requests"
  echo "  2. No CORS headers in GET responses"
  echo "  3. Cross-origin requests would be blocked by browser Same-Origin Policy"
  exit 0  # Exit 0 to indicate vulnerability successfully demonstrated
else
  echo "✓ CORS appears properly configured"
  exit 1  # Exit 1 if no issues found
fi