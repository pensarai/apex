#!/bin/bash

# POC: Verify Missing Cache-Control Headers on Sensitive Pages
# This script demonstrates that the /transactions endpoint lacks Cache-Control headers
# allowing browser caching of sensitive financial transaction data

TARGET_URL="${1:-http://localhost:5003}"
SENSITIVE_PAGES=("/transactions" "/")

echo "=========================================="
echo "Cache-Control Headers Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Check if we can connect to the target
if ! curl -s -m 3 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[ERROR] Cannot connect to $TARGET_URL"
    exit 1
fi

MISSING_HEADERS=0

for page in "${SENSITIVE_PAGES[@]}"; do
    echo "Checking: $page"
    echo "---"
    
    # Make request and capture headers
    RESPONSE=$(curl -s -i "$TARGET_URL$page" 2>&1)
    
    # Check for required cache control headers
    CACHE_CONTROL=$(echo "$RESPONSE" | grep -i '^cache-control:' | head -1)
    PRAGMA=$(echo "$RESPONSE" | grep -i '^pragma:' | head -1)
    EXPIRES=$(echo "$RESPONSE" | grep -i '^expires:' | head -1)
    
    # Check if HTTP 200 response (valid page)
    HTTP_STATUS=$(echo "$RESPONSE" | head -1)
    
    echo "HTTP Status: $HTTP_STATUS"
    
    # Verify missing headers
    if [ -z "$CACHE_CONTROL" ]; then
        echo "❌ MISSING: Cache-Control header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    else
        echo "✓ Cache-Control: $CACHE_CONTROL"
    fi
    
    if [ -z "$PRAGMA" ]; then
        echo "❌ MISSING: Pragma header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    else
        echo "✓ Pragma: $PRAGMA"
    fi
    
    if [ -z "$EXPIRES" ]; then
        echo "❌ MISSING: Expires header"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    else
        echo "✓ Expires: $EXPIRES"
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "=========================================="

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "❌ VULNERABILITY CONFIRMED"
    echo "Missing cache control headers detected on sensitive pages"
    echo "Sensitive data could be cached by browsers and proxies"
    exit 0
else
    echo "✓ All cache control headers present"
    exit 1
fi