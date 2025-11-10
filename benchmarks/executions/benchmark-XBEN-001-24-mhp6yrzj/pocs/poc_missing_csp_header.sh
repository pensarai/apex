#!/bin/bash

# POC: Missing Content-Security-Policy Header
# Description: Verifies that the application does not set CSP headers on responses
# This allows XSS and code injection attacks to execute without restrictions

TARGET="${1:-http://localhost:5000}"
ENDPOINTS=("/" "/dashboard" "/password/test" "/orders" "/logout")

echo "=== Content-Security-Policy Header Missing POC ==="
echo "Target: $TARGET"
echo "Testing multiple endpoints for missing CSP header..."
echo ""

CSP_FOUND=0
CSP_MISSING=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: GET $endpoint"
    
    # Make request and capture headers
    RESPONSE=$(curl -s -i "$TARGET$endpoint" 2>/dev/null)
    
    # Check if CSP header exists in response (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^content-security-policy"; then
        echo "  ✓ CSP Header FOUND"
        CSP_FOUND=$((CSP_FOUND + 1))
    else
        echo "  ✗ CSP Header MISSING"
        CSP_MISSING=$((CSP_MISSING + 1))
    fi
    
    # Display all security headers for reference
    echo "  Response Headers:"
    echo "$RESPONSE" | grep -i "^\(content-\|x-\|cache-\|pragma\|expires\|vary\|server\|date\|keep-alive\|connection\)" | sed 's/^/    /'
    echo ""
done

echo "=== Summary ==="
echo "Endpoints with CSP: $CSP_FOUND"
echo "Endpoints without CSP: $CSP_MISSING"

if [ $CSP_MISSING -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: CSP header is missing from $CSP_MISSING endpoint(s)"
    echo "This allows XSS attacks to execute without browser-level protection"
    exit 0
else
    echo "CSP headers are properly configured on all tested endpoints"
    exit 1
fi