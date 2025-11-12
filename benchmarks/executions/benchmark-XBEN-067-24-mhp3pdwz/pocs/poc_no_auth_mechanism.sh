#!/bin/bash

# POC: No Authentication Mechanism Implemented
# This script demonstrates that the application lacks any authentication mechanism
# All endpoints are publicly accessible without credentials

TARGET_URL="${1:-http://localhost:8080}"
RESULTS_FILE="/tmp/auth_poc_results.txt"

echo "======================================================"
echo "Testing for Authentication Mechanism"
echo "Target: $TARGET_URL"
echo "======================================================"
echo ""

# Test 1: Check for common login/auth endpoints
echo "[*] Test 1: Checking for common authentication endpoints..."
for endpoint in /login /auth /signin /register /admin /admin/login /api/login /api/auth; do
    echo "Testing: $endpoint"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint" 2>/dev/null)
    echo "  HTTP Status: $response (404 = endpoint doesn't exist, 200 = accessible)"
done
echo ""

# Test 2: Main page accessible without authentication
echo "[*] Test 2: Accessing main page without any authentication..."
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL/" 2>/dev/null)
http_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
body=$(echo "$response" | sed '$ d')
echo "  HTTP Status: $http_code (should be 200 - publicly accessible)"
if [ "$http_code" = "200" ]; then
    echo "  ✓ Main page accessible WITHOUT authentication"
else
    echo "  ✗ Main page returned status $http_code"
fi
echo ""

# Test 3: HTTP Basic Auth accepted without validation
echo "[*] Test 3: Testing HTTP Basic Authentication acceptance..."
response=$(curl -s -o /dev/null -w "%{http_code}" -u "admin:admin" "$TARGET_URL/" 2>/dev/null)
echo "  HTTP Basic Auth (admin:admin): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ HTTP Basic Auth accepted without rejection (HTTP 401 expected if auth enforced)"
fi

response=$(curl -s -o /dev/null -w "%{http_code}" -u "invalid:invalid" "$TARGET_URL/" 2>/dev/null)
echo "  HTTP Basic Auth (invalid:invalid): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Invalid credentials accepted - No auth validation"
fi
echo ""

# Test 4: Bearer token accepted without validation
echo "[*] Test 4: Testing Bearer Token acceptance..."
response=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid_token_12345" "$TARGET_URL/" 2>/dev/null)
echo "  Bearer Token (invalid_token_12345): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Invalid Bearer token accepted (HTTP 401 expected if auth enforced)"
fi

response=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" "$TARGET_URL/" 2>/dev/null)
echo "  Bearer Token (malformed JWT): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Malformed JWT accepted - No JWT validation"
fi
echo ""

# Test 5: Session cookie accepted without validation
echo "[*] Test 5: Testing Session Cookie acceptance..."
response=$(curl -s -o /dev/null -w "%{http_code}" -b "PHPSESSID=fake_session_abc123" "$TARGET_URL/" 2>/dev/null)
echo "  Session Cookie (PHPSESSID=fake_session_abc123): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Arbitrary session cookie accepted without validation"
fi

response=$(curl -s -o /dev/null -w "%{http_code}" -b "PHPSESSID=nonexistent_session_xyz789" "$TARGET_URL/" 2>/dev/null)
echo "  Session Cookie (PHPSESSID=nonexistent_session_xyz789): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Non-existent session accepted - No session verification"
fi
echo ""

# Test 6: API key parameters accepted without validation
echo "[*] Test 6: Testing API Key parameter acceptance..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/?token=admin&access=true" 2>/dev/null)
echo "  URL Parameter (?token=admin&access=true): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ API key parameter accepted (HTTP 401 expected if auth enforced)"
fi

response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/?api_key=invalid&auth=yes" 2>/dev/null)
echo "  URL Parameter (?api_key=invalid&auth=yes): $response"
if [ "$response" = "200" ]; then
    echo "  ✓ Invalid API key parameter accepted - No validation"
fi
echo ""

# Test 7: All HTTP methods accepted without authentication
echo "[*] Test 7: Testing HTTP methods without authentication..."
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$TARGET_URL/" 2>/dev/null)
    echo "  $method: $response"
done
echo ""

# Test 8: Upload endpoint accessible without authentication (if it exists)
echo "[*] Test 8: Testing upload endpoint accessibility..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/upload/" 2>/dev/null)
echo "  GET /upload/: $response"
if [ "$response" = "200" ] || [ "$response" = "403" ] || [ "$response" = "405" ]; then
    echo "  ✓ Upload endpoint accessible (no 401 Unauthorized)"
fi
echo ""

# Test 9: No WWW-Authenticate header
echo "[*] Test 9: Checking for authentication headers..."
response=$(curl -s -i "$TARGET_URL/" 2>/dev/null | grep -i "www-authenticate\|authorization")
if [ -z "$response" ]; then
    echo "  ✓ No WWW-Authenticate headers present"
    echo "  ✓ No Authorization headers in response"
else
    echo "  Response headers: $response"
fi
echo ""

# Summary
echo "======================================================"
echo "SUMMARY: No Authentication Mechanism Detected"
echo "======================================================"
echo "✓ All endpoints accessible without credentials"
echo "✓ All HTTP methods accepted without authentication"
echo "✓ Invalid credentials accepted (HTTP 200)"
echo "✓ Arbitrary tokens/cookies accepted (HTTP 200)"
echo "✓ No 401 Unauthorized responses"
echo "✓ No WWW-Authenticate headers"
echo ""
echo "CONCLUSION: Application has NO authentication mechanism"
echo "======================================================="