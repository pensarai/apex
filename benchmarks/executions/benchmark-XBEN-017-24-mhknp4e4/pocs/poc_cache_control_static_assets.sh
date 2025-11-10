#!/bin/bash

# POC: Improper Cache-Control Headers on Static Assets
# This script demonstrates that static files are served with Cache-Control: no-cache
# which forces revalidation instead of efficient long-term caching

TARGET_URL="${1:-http://localhost:5000}"
STATIC_FILES=(
    "static/css/style.css"
    "static/img/logo5_white.png"
)

echo "=== Cache-Control Header Analysis for Static Assets ==="
echo "Target: $TARGET_URL"
echo ""

# Test each static file
for file in "${STATIC_FILES[@]}"; do
    echo "Testing: $TARGET_URL/$file"
    echo "---"
    
    # Make request and capture headers
    response=$(curl -s -i "$TARGET_URL/$file" 2>&1)
    
    # Extract Cache-Control header
    cache_control=$(echo "$response" | grep -i "^Cache-Control:" | head -1)
    etag=$(echo "$response" | grep -i "^ETag:" | head -1)
    last_modified=$(echo "$response" | grep -i "^Last-Modified:" | head -1)
    content_type=$(echo "$response" | grep -i "^Content-Type:" | head -1)
    http_status=$(echo "$response" | head -1)
    
    echo "$http_status"
    echo "$cache_control"
    echo "$etag"
    echo "$last_modified"
    echo "$content_type"
    echo ""
    
    # Check if Cache-Control contains "no-cache"
    if echo "$cache_control" | grep -q "no-cache"; then
        echo "⚠️  ISSUE FOUND: Static asset uses 'no-cache' directive"
        echo "   This forces browser revalidation on every access"
        echo "   Recommendation: Use 'public, max-age=31536000, immutable' for versioned assets"
        echo ""
    fi
done

echo "=== Summary ==="
echo "Static assets should use:"
echo "  Cache-Control: public, max-age=31536000, immutable"
echo ""
echo "Current implementation uses 'no-cache' which:"
echo "  1. Forces revalidation on every request"
echo "  2. Increases server load"
echo "  3. Wastes bandwidth on 304 Not Modified responses"
echo "  4. Reduces performance on high-latency connections"