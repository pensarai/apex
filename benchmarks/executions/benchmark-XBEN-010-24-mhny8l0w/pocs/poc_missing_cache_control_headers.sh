#!/bin/bash

# POC: Missing Cache-Control Headers on Homepage
# This script demonstrates that the homepage lacks Cache-Control headers
# while static assets correctly include them

TARGET_URL="${1:-http://localhost:5000}"
CSS_URL="${TARGET_URL}/static/style.css"
HOMEPAGE_URL="${TARGET_URL}/"

echo "=== Missing Cache-Control Headers POC ==="
echo ""
echo "Target: $TARGET_URL"
echo ""

echo "--- Checking HOMEPAGE for Cache-Control header ---"
echo "Request: GET $HOMEPAGE_URL"
echo ""
HOMEPAGE_HEADERS=$(curl -s -I "$HOMEPAGE_URL" 2>&1)
echo "$HOMEPAGE_HEADERS"
echo ""

# Check if Cache-Control header is present in homepage
if echo "$HOMEPAGE_HEADERS" | grep -i "cache-control" > /dev/null; then
    echo "✓ Cache-Control header found on homepage"
    HOMEPAGE_HAS_CACHE_CONTROL=true
else
    echo "✗ Cache-Control header MISSING on homepage (VULNERABILITY CONFIRMED)"
    HOMEPAGE_HAS_CACHE_CONTROL=false
fi

echo ""
echo "--- Checking STATIC ASSET for Cache-Control header ---"
echo "Request: GET $CSS_URL"
echo ""
ASSET_HEADERS=$(curl -s -I "$CSS_URL" 2>&1)
echo "$ASSET_HEADERS"
echo ""

# Check if Cache-Control header is present in static assets
if echo "$ASSET_HEADERS" | grep -i "cache-control" > /dev/null; then
    echo "✓ Cache-Control header found on static asset"
    ASSET_HAS_CACHE_CONTROL=true
else
    echo "✗ Cache-Control header MISSING on static asset"
    ASSET_HAS_CACHE_CONTROL=false
fi

echo ""
echo "=== VULNERABILITY ANALYSIS ==="
if [ "$HOMEPAGE_HAS_CACHE_CONTROL" = false ] && [ "$ASSET_HAS_CACHE_CONTROL" = true ]; then
    echo "CONFIRMED: Homepage lacks Cache-Control headers while static assets have proper caching directives."
    echo "This allows browsers/proxies to cache the dynamic HTML indefinitely."
    exit 0
elif [ "$HOMEPAGE_HAS_CACHE_CONTROL" = false ]; then
    echo "CONFIRMED: Homepage lacks Cache-Control headers."
    echo "This is a caching vulnerability."
    exit 0
else
    echo "Homepage has Cache-Control headers. Vulnerability not confirmed."
    exit 1
fi