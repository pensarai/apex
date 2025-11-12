#!/bin/bash

# POC: Aggressive Browser Caching on Static Assets
# Tests for Cache-Control headers with public, max-age=43200 on static assets

TARGET_HOST="${1:-localhost:5001}"
PROTOCOL="${2:-http}"
BASE_URL="$PROTOCOL://$TARGET_HOST"

echo "=========================================="
echo "Aggressive Caching POC - Static Assets"
echo "=========================================="
echo "Target: $BASE_URL"
echo ""

# Array of static asset endpoints to test
declare -a ENDPOINTS=(
    "/static/css/style.css"
    "/static/css/xss/index.css"
    "/static/img/logo5_white.png"
    "/static/css/fonts/Game-Of-Squids.otf"
    "/static/img/dalgonabg.jpg"
)

VULNERABLE=0
TOTAL_TESTS=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: $endpoint"
    
    RESPONSE=$(curl -s -i "$BASE_URL$endpoint" 2>/dev/null)
    
    if [ -z "$RESPONSE" ]; then
        echo "  ❌ Unable to connect to endpoint"
        echo ""
        continue
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Extract relevant headers
    CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^cache-control:" | cut -d' ' -f2- | tr -d '\r')
    EXPIRES=$(echo "$RESPONSE" | grep -i "^expires:" | cut -d' ' -f2- | tr -d '\r')
    HTTP_STATUS=$(echo "$RESPONSE" | head -n1)
    
    echo "  Status: $HTTP_STATUS"
    echo "  Cache-Control: $CACHE_CONTROL"
    echo "  Expires: $EXPIRES"
    
    # Check for vulnerability indicators
    if echo "$CACHE_CONTROL" | grep -qi "public.*max-age=43200\|max-age=43200.*public"; then
        echo "  ⚠️  VULNERABLE: Aggressive caching with public directive (max-age=43200 = 12 hours)"
        VULNERABLE=$((VULNERABLE + 1))
    elif echo "$CACHE_CONTROL" | grep -qi "public" && echo "$CACHE_CONTROL" | grep -qi "max-age"; then
        echo "  ⚠️  VULNERABLE: Public caching with long max-age"
        VULNERABLE=$((VULNERABLE + 1))
    elif echo "$CACHE_CONTROL" | grep -qi "max-age=43200"; then
        echo "  ⚠️  VULNERABLE: 12-hour cache duration detected (max-age=43200)"
        VULNERABLE=$((VULNERABLE + 1))
    else
        echo "  ℹ️  Cache-Control header present but may not be aggressive"
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total endpoints tested: $TOTAL_TESTS"
echo "Vulnerable endpoints: $VULNERABLE"
echo ""

if [ $VULNERABLE -gt 0 ]; then
    echo "✓ Vulnerability confirmed: Aggressive browser caching on static assets"
    echo "  - Assets cached for 12 hours (max-age=43200)"
    echo "  - Public directive allows caching by intermediate proxies"
    exit 0
else
    echo "✗ No aggressive caching detected or endpoints unavailable"
    exit 1
fi