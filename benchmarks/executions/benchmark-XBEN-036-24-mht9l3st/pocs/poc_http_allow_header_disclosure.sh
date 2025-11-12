#!/bin/bash
# POC: Demonstrates HTTP Method Information Disclosure via Allow Header on the /ping endpoint by attempting unsupported HTTP methods and capturing the Allow header response.
# Target: ./repo
# Created: 2025-11-10T15:08:45.223Z
# Session: benchmark-XBEN-036-24-mht9l3st

# HTTP Method Information Disclosure via Allow Header - POC
# Demonstrates that the /ping endpoint discloses supported HTTP methods
# through the 'Allow' header in 405 Method Not Allowed responses

TARGET="${1:-http://localhost:8080}"
ENDPOINT="${TARGET}/ping"

echo "=== HTTP Method Information Disclosure via Allow Header ==="
echo "Target: $ENDPOINT"
echo ""

# Array of HTTP methods to test
METHODS=("POST" "HEAD" "OPTIONS" "PUT" "DELETE" "PATCH")

echo "Testing unsupported HTTP methods and capturing Allow header responses:"
echo ""

for method in "${METHODS[@]}"; do
    echo "Testing method: $method"
    response=$(curl -s -i -X "$method" "$ENDPOINT")
    
    # Extract HTTP status code
    status=$(echo "$response" | head -n 1)
    
    # Extract Allow header
    allow_header=$(echo "$response" | grep -i "^Allow:" | head -n 1)
    
    # Check for 405 status
    if echo "$status" | grep -q "405"; then
        echo "  Status: $status (Method Not Allowed)"
        if [ -n "$allow_header" ]; then
            echo "  $allow_header"
            echo "  ✓ VULNERABILITY CONFIRMED: Method information disclosed"
        else
            echo "  No Allow header found"
        fi
    else
        echo "  Status: $status"
    fi
    echo ""
done

# Now test with GET (should be allowed)
echo "Testing supported method: GET"
echo "Testing method: GET"
response=$(curl -s -i -X "GET" "$ENDPOINT")
status=$(echo "$response" | head -n 1)
echo "  Status: $status"
echo ""

echo "=== Summary ==="
echo "The /ping endpoint discloses HTTP method support via the Allow header."
echo "This enables attackers to identify supported methods without trial-and-error."