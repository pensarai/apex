#!/bin/bash

# POC: Missing HSTS Header Verification
# Tests multiple endpoints to confirm absence of Strict-Transport-Security header

TARGET_URL="${1:-http://localhost:5003}"
ENDPOINTS=("/" "/login" "/add_prescription" "/prescriptions" "/graphql")

echo "=========================================="
echo "HSTS Header Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

HSTS_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET_URL$endpoint"
    echo "---"
    
    # Make HTTP request and check for HSTS header
    RESPONSE=$(curl -s -i "$TARGET_URL$endpoint" 2>/dev/null)
    
    # Extract HSTS header
    HSTS_HEADER=$(echo "$RESPONSE" | grep -i "strict-transport-security" | head -1)
    
    if [ -z "$HSTS_HEADER" ]; then
        echo "❌ HSTS Header: MISSING"
        echo "Vulnerability: HTTP Strict-Transport-Security header is not set"
    else
        echo "✓ HSTS Header: PRESENT"
        echo "$HSTS_HEADER"
        HSTS_FOUND=$((HSTS_FOUND + 1))
    fi
    
    # Also show HTTP/HTTPS protocol
    PROTOCOL=$(echo "$RESPONSE" | head -1 | grep -oE "HTTP/[0-9.]+")
    echo "Protocol: $PROTOCOL"
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Total endpoints tested: ${#ENDPOINTS[@]}"
echo "Endpoints with HSTS: $HSTS_FOUND"
echo "Endpoints without HSTS: $((${#ENDPOINTS[@]} - HSTS_FOUND))"
echo ""

if [ $HSTS_FOUND -eq 0 ]; then
    echo "❌ VULNERABILITY CONFIRMED: HSTS header missing from ALL tested endpoints"
    echo ""
    echo "Recommendation:"
    echo "Add HSTS header to all HTTPS responses:"
    echo "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    exit 0
else
    echo "⚠️  Some endpoints have HSTS, but coverage is incomplete"
    exit 0
fi