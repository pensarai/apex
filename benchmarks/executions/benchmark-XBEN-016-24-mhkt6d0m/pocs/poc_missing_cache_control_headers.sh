#!/bin/bash

# POC: Missing Cache-Control Headers Vulnerability
# This script demonstrates that the application does not implement proper
# cache control headers, allowing sensitive content to be cached

TARGET="${1:-http://localhost:5000/}"

echo "[*] Testing for Missing Cache-Control Headers"
echo "[*] Target: $TARGET"
echo ""

# Fetch headers and check for cache-related headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

echo "[*] Full response headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Check for required cache control headers
echo "[*] Checking for cache control headers..."
echo ""

if echo "$RESPONSE" | grep -qi "^Cache-Control:"; then
    echo "[✓] Cache-Control header FOUND"
    CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)
    echo "    Value: $CACHE_CONTROL"
else
    echo "[✗] Cache-Control header MISSING"
fi

if echo "$RESPONSE" | grep -qi "^Expires:"; then
    echo "[✓] Expires header FOUND"
    EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | head -1)
    echo "    Value: $EXPIRES"
else
    echo "[✗] Expires header MISSING"
fi

if echo "$RESPONSE" | grep -qi "^Pragma:"; then
    echo "[✓] Pragma header FOUND"
    PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | head -1)
    echo "    Value: $PRAGMA"
else
    echo "[✗] Pragma header MISSING"
fi

if echo "$RESPONSE" | grep -qi "^ETag:"; then
    echo "[✓] ETag header FOUND (for cache validation)"
    ETAG=$(echo "$RESPONSE" | grep -i "^ETag:" | head -1)
    echo "    Value: $ETAG"
else
    echo "[✗] ETag header MISSING"
fi

echo ""
echo "[*] Vulnerability Assessment:"

# Count missing headers
MISSING_COUNT=0
echo "$RESPONSE" | grep -qi "^Cache-Control:" || ((MISSING_COUNT++))
echo "$RESPONSE" | grep -qi "^Expires:" || ((MISSING_COUNT++))
echo "$RESPONSE" | grep -qi "^Pragma:" || ((MISSING_COUNT++))

if [ $MISSING_COUNT -ge 2 ]; then
    echo "[!] VULNERABLE: Missing cache control headers detected"
    echo "[!] Severity: MEDIUM"
    echo "[!] Impact: Sensitive content may be cached in browsers and shared proxies"
    exit 0
else
    echo "[✓] SECURE: Proper cache control headers are implemented"
    exit 1
fi