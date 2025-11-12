#!/bin/bash

# POC: Missing Cache-Control Headers on Logout Response
# This script demonstrates that the logout endpoint does not include proper cache control headers
# which could allow the redirect response to be cached by intermediaries or browsers

TARGET_URL="${1:-http://localhost/accounts/logout/}"

echo "========================================"
echo "Cache-Control Headers Verification POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Perform a HEAD request to get response headers without body
echo "[*] Sending HEAD request to logout endpoint..."
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

echo "[*] Response headers received:"
echo "$RESPONSE"
echo ""

# Check for required cache control headers
echo "[*] Analyzing response headers..."
echo ""

# Extract specific headers
HAS_CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" || echo "MISSING")
HAS_PRAGMA=$(echo "$RESPONSE" | grep -i "^pragma:" || echo "MISSING")
HAS_EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" || echo "MISSING")
HAS_LOCATION=$(echo "$RESPONSE" | grep -i "^location:" || echo "MISSING")

echo "Cache-Control Header: $HAS_CACHE_CONTROL"
echo "Pragma Header: $HAS_PRAGMA"
echo "Expires Header: $HAS_EXPIRES"
echo "Location Header: $HAS_LOCATION"
echo ""

# Check if response is a redirect
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1)
echo "HTTP Status: $HTTP_STATUS"
echo ""

# Vulnerability assessment
echo "========================================"
echo "VULNERABILITY ASSESSMENT"
echo "========================================"

CACHE_CONTROL_MISSING=0
if echo "$HAS_CACHE_CONTROL" | grep -q "MISSING"; then
    echo "❌ VULNERABLE: Cache-Control header is MISSING"
    CACHE_CONTROL_MISSING=1
else
    echo "✓ Cache-Control header present"
fi

if echo "$HAS_PRAGMA" | grep -q "MISSING"; then
    echo "❌ WARNING: Pragma header (HTTP/1.0 compatibility) is MISSING"
fi

if echo "$HAS_EXPIRES" | grep -q "MISSING"; then
    echo "❌ WARNING: Expires header is MISSING"
fi

if echo "$HTTP_STATUS" | grep -q "302\|301\|303\|307"; then
    echo "⚠️  Response is a redirect - particularly sensitive to caching issues"
fi

echo ""

if [ $CACHE_CONTROL_MISSING -eq 1 ]; then
    echo "========================================"
    echo "FINDING CONFIRMED"
    echo "========================================"
    echo "The logout endpoint response lacks proper Cache-Control headers."
    echo "This allows the response to be cached by:"
    echo "  - Browser caches"
    echo "  - Proxy caches"
    echo "  - CDN caches"
    echo "  - ISP-level caches"
    echo ""
    echo "Recommended headers to add:"
    echo "  Cache-Control: no-cache, no-store, must-revalidate"
    echo "  Pragma: no-cache"
    echo "  Expires: 0"
    exit 0
else
    echo "Cache-Control headers are present - vulnerability not confirmed"
    exit 1
fi