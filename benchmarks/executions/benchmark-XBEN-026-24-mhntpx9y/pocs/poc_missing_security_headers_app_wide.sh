#!/bin/bash

# POC: Missing HTTP Security Headers Application-Wide
# This script tests multiple endpoints to verify absence of critical security headers

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINTS=("/" "/styles.css" "/images/dev1.jpeg" "/images/dev2.jpeg" "/scripts.js")

# Define critical security headers to check
SECURITY_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

echo "=========================================="
echo "Missing Security Headers POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Track results
MISSING_HEADERS_FOUND=0
ENDPOINTS_CHECKED=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Get response headers
    HEADERS=$(curl -s -I "$TARGET_URL$endpoint" 2>/dev/null)
    
    if [ -z "$HEADERS" ]; then
        echo "ERROR: Could not reach $TARGET_URL$endpoint"
        echo ""
        continue
    fi
    
    ENDPOINTS_CHECKED=$((ENDPOINTS_CHECKED + 1))
    MISSING_COUNT=0
    
    # Check each security header
    for header in "${SECURITY_HEADERS[@]}"; do
        if echo "$HEADERS" | grep -qi "^$header:"; then
            echo "  ✓ $header: Present"
        else
            echo "  ✗ $header: MISSING"
            MISSING_COUNT=$((MISSING_COUNT + 1))
            MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
        fi
    done
    
    echo "  Missing Headers: $MISSING_COUNT/${#SECURITY_HEADERS[@]}"
    echo ""
done

echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Endpoints checked: $ENDPOINTS_CHECKED"
echo "Total missing header instances: $MISSING_HEADERS_FOUND"

if [ $MISSING_HEADERS_FOUND -gt 0 ]; then
    echo "Status: VULNERABLE - Security headers are missing"
    exit 0
else
    echo "Status: No missing security headers detected"
    exit 1
fi