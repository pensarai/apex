#!/bin/bash

# POC: Last-Modified Header Disclosure
# This script demonstrates that all HTTP responses include the Last-Modified header,
# which exposes file modification timestamps

TARGET="http://localhost:8000"
ENDPOINTS=(
    "/"
    "/index.html"
    "/scripts.js"
    "/styles.css"
    "/dev1.jpeg"
    "/dev2.jpeg"
)

echo "=========================================="
echo "Last-Modified Header Disclosure POC"
echo "=========================================="
echo ""
echo "Testing for Last-Modified header exposure on all endpoints:"
echo ""

VULNERABLE=0
TIMESTAMPS=()

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: $TARGET$endpoint"
    RESPONSE=$(curl -s -i "$TARGET$endpoint" 2>&1)
    LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "^Last-Modified:" | head -1)
    
    if [ -n "$LAST_MODIFIED" ]; then
        echo "  ✓ VULNERABLE: $LAST_MODIFIED"
        TIMESTAMPS+=("$LAST_MODIFIED")
        VULNERABLE=$((VULNERABLE + 1))
    else
        echo "  ✗ Not found"
    fi
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Total endpoints tested: ${#ENDPOINTS[@]}"
echo "Endpoints exposing Last-Modified: $VULNERABLE"
echo ""

if [ $VULNERABLE -eq ${#ENDPOINTS[@]} ]; then
    echo "✓ VULNERABILITY CONFIRMED: All endpoints expose Last-Modified header"
    echo ""
    echo "Sample timestamps found:"
    for ts in "${TIMESTAMPS[@]}"; do
        echo "  - $ts"
    done
    exit 0
else
    echo "✗ Vulnerability not fully confirmed"
    exit 1
fi