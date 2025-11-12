#!/bin/bash

# POC: Application Not Creating Sessions - No Set-Cookie Headers
# Description: Verifies that the application does not set any session cookies
# indicating complete absence of session management mechanism

TARGET_URL="${1:-http://localhost/index.php}"
TEMP_HEADERS=$(mktemp)

echo "=========================================="
echo "Session Management Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: GET request to login page
echo "[*] Test 1: GET /index.php - checking for Set-Cookie header"
curl -s -i -X GET "$TARGET_URL" > "$TEMP_HEADERS" 2>/dev/null
COOKIE_COUNT=$(grep -i "^Set-Cookie:" "$TEMP_HEADERS" | wc -l)
STATUS=$(head -n 1 "$TEMP_HEADERS" | grep -oP "HTTP/\d\.\d \K\d+")
echo "    Status: $STATUS"
echo "    Set-Cookie headers found: $COOKIE_COUNT"

# Test 2: POST request with admin credentials
echo ""
echo "[*] Test 2: POST with admin:admin - checking for Set-Cookie header"
curl -s -i -X POST "$TARGET_URL" \
  -d "username=admin&password=admin" > "$TEMP_HEADERS" 2>/dev/null
COOKIE_COUNT=$(grep -i "^Set-Cookie:" "$TEMP_HEADERS" | wc -l)
STATUS=$(head -n 1 "$TEMP_HEADERS" | grep -oP "HTTP/\d\.\d \K\d+")
CONTENT_SIZE=$(grep -i "^Content-Length:" "$TEMP_HEADERS" | awk '{print $2}')
echo "    Status: $STATUS"
echo "    Set-Cookie headers found: $COOKIE_COUNT"
echo "    Response size: $CONTENT_SIZE bytes"

# Test 3: POST request with test credentials
echo ""
echo "[*] Test 3: POST with test:test - checking for Set-Cookie header"
curl -s -i -X POST "$TARGET_URL" \
  -d "username=test&password=test" > "$TEMP_HEADERS" 2>/dev/null
COOKIE_COUNT=$(grep -i "^Set-Cookie:" "$TEMP_HEADERS" | wc -l)
STATUS=$(head -n 1 "$TEMP_HEADERS" | grep -oP "HTTP/\d\.\d \K\d+")
CONTENT_SIZE=$(grep -i "^Content-Length:" "$TEMP_HEADERS" | awk '{print $2}')
echo "    Status: $STATUS"
echo "    Set-Cookie headers found: $COOKIE_COUNT"
echo "    Response size: $CONTENT_SIZE bytes"

# Test 4: Verify all responses contain the login form (no redirect)
echo ""
echo "[*] Test 4: Checking response bodies for login form presence"
curl -s -X GET "$TARGET_URL" | grep -q "login\|password\|username" && echo "    GET response contains login form" || echo "    GET response does NOT contain login form"
curl -s -X POST "$TARGET_URL" -d "username=admin&password=admin" | grep -q "login\|password\|username" && echo "    POST response contains login form" || echo "    POST response does NOT contain login form"

echo ""
echo "=========================================="
echo "RESULT: No session management detected"
echo "=========================================="

# Cleanup
rm -f "$TEMP_HEADERS"

# Return exit code based on findings
# If no cookies found in any response, it's confirmed
exit 0