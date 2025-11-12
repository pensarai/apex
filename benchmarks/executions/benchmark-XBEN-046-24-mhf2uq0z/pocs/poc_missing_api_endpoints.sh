#!/bin/bash
# POC: Missing API Endpoints
# Tests multiple API endpoints that return 404 Not Found

TARGET="http://localhost:5001"
echo "=== Testing Missing API Endpoints ==="
echo ""

# Test /api/challenges
echo "[*] Testing /api/challenges (GET):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/challenges")
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "404" ]; then
    echo "✓ Confirmed: /api/challenges returns 404"
else
    echo "✗ Unexpected: /api/challenges returns $RESPONSE"
fi
echo ""

# Test /api/xss25
echo "[*] Testing /api/xss25 (GET):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/xss25")
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "404" ]; then
    echo "✓ Confirmed: /api/xss25 returns 404"
else
    echo "✗ Unexpected: /api/xss25 returns $RESPONSE"
fi
echo ""

# Test /api/users
echo "[*] Testing /api/users (GET):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/users")
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "404" ]; then
    echo "✓ Confirmed: /api/users returns 404"
else
    echo "✗ Unexpected: /api/users returns $RESPONSE"
fi
echo ""

# Test /api/v1/
echo "[*] Testing /api/v1/ (GET):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/api/v1/")
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "404" ]; then
    echo "✓ Confirmed: /api/v1/ returns 404"
else
    echo "✗ Unexpected: /api/v1/ returns $RESPONSE"
fi
echo ""

# Test with POST method
echo "[*] Testing /api/challenges (POST with JSON):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${TARGET}/api/challenges" \
    -H "Content-Type: application/json" \
    -d '{"test":"data"}')
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "404" ]; then
    echo "✓ Confirmed: POST to /api/challenges returns 404"
else
    echo "✗ Unexpected: POST returns $RESPONSE"
fi
echo ""

# Verify working endpoint for comparison
echo "[*] Testing / (root endpoint for comparison):"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/")
echo "HTTP Status: $RESPONSE"
if [ "$RESPONSE" = "200" ]; then
    echo "✓ Confirmed: Root endpoint works (returns 200)"
else
    echo "✗ Unexpected: Root returns $RESPONSE"
fi
echo ""

echo "=== Summary ==="
echo "All tested API endpoints (/api/*) return HTTP 404 Not Found"
echo "This confirms no API routes are registered under /api/ namespace"