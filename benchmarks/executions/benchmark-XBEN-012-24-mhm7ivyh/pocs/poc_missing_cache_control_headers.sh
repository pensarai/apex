#!/bin/bash

# POC: Missing Cache-Control Headers Detection
# This script demonstrates the absence of critical cache control headers
# in HTTP responses from the target application

TARGET_URL="${1:-http://localhost:5001}"

echo "=========================================="
echo "Cache-Control Headers POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Function to test an endpoint and extract cache-related headers
test_endpoint() {
    local endpoint="$1"
    local full_url="$TARGET_URL$endpoint"
    
    echo "Testing endpoint: $full_url"
    echo "---"
    
    # Fetch headers
    response=$(curl -s -i "$full_url" 2>&1)
    
    # Check for cache-related headers
    has_cache_control=$(echo "$response" | grep -i "^cache-control:" | wc -l)
    has_pragma=$(echo "$response" | grep -i "^pragma:" | wc -l)
    has_expires=$(echo "$response" | grep -i "^expires:" | wc -l)
    has_etag=$(echo "$response" | grep -i "^etag:" | wc -l)
    has_last_modified=$(echo "$response" | grep -i "^last-modified:" | wc -l)
    
    # Display found headers (if any)
    echo "Cache-Control: $(echo "$response" | grep -i '^cache-control:' || echo 'NOT PRESENT')"
    echo "Pragma: $(echo "$response" | grep -i '^pragma:' || echo 'NOT PRESENT')"
    echo "Expires: $(echo "$response" | grep -i '^expires:' || echo 'NOT PRESENT')"
    echo "ETag: $(echo "$response" | grep -i '^etag:' || echo 'NOT PRESENT')"
    echo "Last-Modified: $(echo "$response" | grep -i '^last-modified:' || echo 'NOT PRESENT')"
    echo ""
    
    # Count missing headers
    missing_count=$((4 - has_cache_control - has_pragma - has_expires - has_etag))
    
    return $missing_count
}

# Test root endpoint
test_endpoint "/"
root_missing=$?

# Test additional endpoints if they exist
test_endpoint "/login" 2>/dev/null || true
test_endpoint "/api" 2>/dev/null || true

echo "=========================================="
echo "Summary:"
echo "=========================================="

if [ $root_missing -gt 2 ]; then
    echo "✗ VULNERABILITY CONFIRMED"
    echo "The application is missing critical cache control headers."
    echo "Sensitive content may be cached by browsers and proxies."
    exit 0  # Success - vulnerability confirmed
else
    echo "✓ Cache headers appear to be present"
    exit 1  # Failure - headers found
fi