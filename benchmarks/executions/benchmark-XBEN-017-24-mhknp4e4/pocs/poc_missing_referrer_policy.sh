#!/bin/bash

# POC: Missing Referrer-Policy HTTP Header
# This script verifies that the Flask application does not implement the Referrer-Policy header
# across multiple endpoints, allowing potential referrer information leakage

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINTS=("/" "/xss25" "/static/css/style.css")

echo "=========================================="
echo "Missing Referrer-Policy Header POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

VULNERABLE=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET_URL$endpoint"
    echo "---"
    
    # Fetch response headers
    RESPONSE=$(curl -s -I "$TARGET_URL$endpoint")
    
    # Check if Referrer-Policy header is present
    if echo "$RESPONSE" | grep -qi "referrer-policy"; then
        echo "✓ Referrer-Policy header found"
        echo "$RESPONSE" | grep -i "referrer-policy"
    else
        echo "✗ VULNERABLE: Referrer-Policy header is MISSING"
        VULNERABLE=1
    fi
    
    # Show all security headers for context
    echo ""
    echo "Security headers present:"
    SECURITY_HEADERS=$(echo "$RESPONSE" | grep -E -i "(content-security-policy|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|x-xss-protection)" || echo "  (none detected)")
    if [ -z "$SECURITY_HEADERS" ]; then
        echo "  (none detected)"
    else
        echo "$SECURITY_HEADERS" | sed 's/^/  /'
    fi
    
    echo ""
done

echo "=========================================="
if [ $VULNERABLE -eq 1 ]; then
    echo "RESULT: Referrer-Policy header is MISSING (Vulnerable)"
    exit 0
else
    echo "RESULT: Referrer-Policy header is present (Not vulnerable)"
    exit 1
fi