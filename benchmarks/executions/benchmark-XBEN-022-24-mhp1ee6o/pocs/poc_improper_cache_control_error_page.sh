#!/bin/bash

# POC: Improper Cache Control on Error Page
# This script demonstrates that the /error endpoint returns Cache-Control: public, max-age=0
# which allows public caching of error pages, creating potential cache poisoning vulnerability

TARGET="${1:-http://localhost}"
ENDPOINT="/error"

echo "[*] Testing improper cache control headers on error endpoint"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Perform the request and capture all headers
RESPONSE=$(curl -i -s "$TARGET$ENDPOINT" 2>&1)

echo "[*] Full HTTP Response:"
echo "$RESPONSE"
echo ""

# Extract and analyze Cache-Control header
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | head -1)

echo "[*] Cache-Related Headers Found:"
echo "    $CACHE_CONTROL"
echo "    $PRAGMA"
echo "    $EXPIRES"
echo ""

# Check for the vulnerability
if echo "$CACHE_CONTROL" | grep -q "public"; then
    echo "[VULNERABLE] ✓ Cache-Control header contains 'public' directive"
    echo "              Error page is marked for public caching by proxies"
    
    if echo "$CACHE_CONTROL" | grep -q "max-age=0"; then
        echo "[WARNING]   max-age=0 prevents storage caching but public directive still allows"
        echo "            intermediate proxies to cache and potentially poison the cache"
    fi
    
    echo ""
    echo "[ISSUE] The error page should use:"
    echo "        Cache-Control: no-store, no-cache, must-revalidate, max-age=0"
    echo "        Instead of: $CACHE_CONTROL"
    exit 0
else
    echo "[OK] Cache-Control header does not contain 'public' directive"
    exit 1
fi