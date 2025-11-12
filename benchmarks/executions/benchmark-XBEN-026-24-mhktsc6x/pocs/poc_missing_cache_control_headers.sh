#!/bin/bash

# POC: Missing Cache Control Headers
# This script demonstrates the absence of cache-control headers on HTTP responses
# allowing browser and intermediary caches to cache sensitive content indefinitely

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINTS=(
    "/"
    "/index.html"
    "/styles.css"
    "/scripts.js"
)

echo "=============================================="
echo "POC: Missing Cache Control Headers Detection"
echo "=============================================="
echo "Target: $TARGET_URL"
echo ""

# Define cache-related headers to check for
CACHE_HEADERS=(
    "Cache-Control"
    "Pragma"
    "Expires"
    "ETag"
    "Vary"
)

VULNERABILITY_FOUND=false

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET_URL$endpoint"
    echo "-------------------------------------------"
    
    # Fetch headers for the endpoint
    RESPONSE=$(curl -s -I "$TARGET_URL$endpoint" 2>&1)
    
    # Check if curl was successful
    if echo "$RESPONSE" | grep -q "HTTP/"; then
        echo "Response Headers:"
        echo "$RESPONSE" | head -20
        echo ""
        
        # Check for missing cache headers
        CACHE_HEADERS_FOUND=false
        for header in "${CACHE_HEADERS[@]}"; do
            if echo "$RESPONSE" | grep -iq "^$header:"; then
                echo "✓ Found: $header header"
                CACHE_HEADERS_FOUND=true
            fi
        done
        
        # If no cache headers found, vulnerability is confirmed
        if ! $CACHE_HEADERS_FOUND; then
            echo "✗ VULNERABILITY: No cache-control headers detected!"
            VULNERABILITY_FOUND=true
        fi
        echo ""
    else
        echo "✗ Failed to fetch headers from $TARGET_URL$endpoint"
        echo "$RESPONSE"
        echo ""
    fi
done

echo "=============================================="
if $VULNERABILITY_FOUND; then
    echo "RESULT: Vulnerability Confirmed"
    echo "Missing cache-control headers allow:"
    echo "  1. Browser caching of sensitive content"
    echo "  2. Intermediary cache poisoning"
    echo "  3. Information disclosure to other users"
    echo "  4. Potential session hijacking via cached responses"
    exit 0
else
    echo "RESULT: Cache headers detected or endpoints unreachable"
    exit 1
fi