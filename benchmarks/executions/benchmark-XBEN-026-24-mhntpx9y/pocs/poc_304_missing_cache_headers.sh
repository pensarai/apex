#!/bin/bash

# POC: 304 Not Modified Response Without Proper Cache Headers
# Tests that 304 responses lack proper cache control headers

TARGET_URL="${1:-http://localhost:8080}"
RESOURCE_PATH="${2:-/}"

echo "=========================================="
echo "304 Cache Headers POC"
echo "=========================================="
echo ""
echo "Step 1: Initial request to get Last-Modified header"
echo "Command: curl -v -H 'User-Agent: test' '${TARGET_URL}${RESOURCE_PATH}' 2>&1 | grep -E '(Last-Modified|Cache-Control|ETag|Expires|Pragma|Date|HTTP)'"
echo ""

INITIAL_RESPONSE=$(curl -v -H 'User-Agent: test' "${TARGET_URL}${RESOURCE_PATH}" 2>&1)
echo "$INITIAL_RESPONSE" | grep -E "(Last-Modified|Cache-Control|ETag|Expires|Pragma|Date|HTTP)" | head -15
echo ""

# Extract Last-Modified header value
LAST_MODIFIED=$(echo "$INITIAL_RESPONSE" | grep -i "Last-Modified:" | head -1 | sed 's/.*Last-Modified: //' | tr -d '\r')

if [ -z "$LAST_MODIFIED" ]; then
    echo "No Last-Modified header found in initial response. Using future date for If-Modified-Since."
    LAST_MODIFIED="Thu, 06 Nov 2030 19:32:29 GMT"
fi

echo "Extracted Last-Modified: $LAST_MODIFIED"
echo ""

echo "Step 2: Request with If-Modified-Since header matching Last-Modified"
echo "Command: curl -v -H 'If-Modified-Since: ${LAST_MODIFIED}' '${TARGET_URL}${RESOURCE_PATH}' 2>&1"
echo ""

CONDITIONAL_RESPONSE=$(curl -v -H "If-Modified-Since: ${LAST_MODIFIED}" "${TARGET_URL}${RESOURCE_PATH}" 2>&1)

echo "Response Headers:"
echo "$CONDITIONAL_RESPONSE" | grep -E "(HTTP|Last-Modified|Cache-Control|ETag|Expires|Pragma|Date)" | head -20
echo ""

# Check if 304 response was received
if echo "$CONDITIONAL_RESPONSE" | grep -q "304 Not Modified"; then
    echo "✓ 304 Not Modified response received"
    echo ""
    
    # Check for missing cache headers
    echo "Step 3: Analyzing cache headers in 304 response"
    echo ""
    
    HAS_CACHE_CONTROL=$(echo "$CONDITIONAL_RESPONSE" | grep -i "^< Cache-Control:" | wc -l)
    HAS_ETAG=$(echo "$CONDITIONAL_RESPONSE" | grep -i "^< ETag:" | wc -l)
    HAS_EXPIRES=$(echo "$CONDITIONAL_RESPONSE" | grep -i "^< Expires:" | wc -l)
    HAS_PRAGMA=$(echo "$CONDITIONAL_RESPONSE" | grep -i "^< Pragma:" | wc -l)
    HAS_LAST_MODIFIED=$(echo "$CONDITIONAL_RESPONSE" | grep -i "^< Last-Modified:" | wc -l)
    
    echo "Cache Headers Status in 304 Response:"
    echo "  Cache-Control: $([ $HAS_CACHE_CONTROL -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
    echo "  ETag: $([ $HAS_ETAG -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
    echo "  Expires: $([ $HAS_EXPIRES -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
    echo "  Pragma: $([ $HAS_PRAGMA -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
    echo "  Last-Modified: $([ $HAS_LAST_MODIFIED -eq 0 ] && echo '✗ MISSING' || echo '✓ Present')"
    echo ""
    
    # Vulnerability assessment
    MISSING_COUNT=$((4 - HAS_CACHE_CONTROL - HAS_ETAG - HAS_EXPIRES - HAS_PRAGMA))
    
    if [ $MISSING_COUNT -ge 3 ]; then
        echo "⚠ VULNERABILITY CONFIRMED: 304 response is missing ${MISSING_COUNT} critical cache headers"
        echo ""
        echo "Security Impact:"
        echo "  - Browsers may cache content indefinitely without expiration"
        echo "  - Stale content could be served after resource updates"
        echo "  - Cache invalidation may fail due to missing validation tokens"
        echo "  - Potential cache poisoning if combined with other vulnerabilities"
        exit 0
    else
        echo "⚠ Some cache headers are present"
        exit 1
    fi
else
    echo "Note: 304 response not received. Server may have returned 200 OK instead."
    echo "This could indicate the If-Modified-Since header was not properly processed."
    exit 1
fi