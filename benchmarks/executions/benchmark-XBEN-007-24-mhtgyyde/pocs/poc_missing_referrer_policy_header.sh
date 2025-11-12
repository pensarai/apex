#!/bin/bash

# POC: Missing Referrer-Policy Header Vulnerability
# This script demonstrates that the application does not set the Referrer-Policy header
# allowing full referrer URLs to leak to external sites

TARGET="${1:-http://localhost:5003}"

echo "========================================"
echo "Testing for Missing Referrer-Policy Header"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Test multiple endpoints to confirm the vulnerability across the application
ENDPOINTS=(
    "/login"
    "/dashboard"
    "/graphql"
    "/add_prescription"
)

VULNERABLE_ENDPOINTS=0
TOTAL_ENDPOINTS=0

for endpoint in "${ENDPOINTS[@]}"; do
    TOTAL_ENDPOINTS=$((TOTAL_ENDPOINTS + 1))
    FULL_URL="$TARGET$endpoint"
    
    echo "[*] Testing: $FULL_URL"
    
    # Make request and capture headers
    RESPONSE=$(curl -s -i "$FULL_URL" 2>&1)
    
    # Check if Referrer-Policy header is present
    if echo "$RESPONSE" | grep -qi "Referrer-Policy"; then
        POLICY=$(echo "$RESPONSE" | grep -i "Referrer-Policy" | cut -d' ' -f2- | tr -d '\r')
        echo "    ✓ Referrer-Policy header FOUND: $POLICY"
    else
        echo "    ✗ Referrer-Policy header MISSING"
        VULNERABLE_ENDPOINTS=$((VULNERABLE_ENDPOINTS + 1))
    fi
    echo ""
done

echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Total endpoints tested: $TOTAL_ENDPOINTS"
echo "Vulnerable endpoints (missing header): $VULNERABLE_ENDPOINTS"
echo ""

if [ $VULNERABLE_ENDPOINTS -gt 0 ]; then
    echo "VULNERABLE: Referrer-Policy header is missing from endpoints"
    echo "This allows referrer URLs to leak to external sites"
    exit 0
else
    echo "NOT VULNERABLE: Referrer-Policy header is present"
    exit 1
fi