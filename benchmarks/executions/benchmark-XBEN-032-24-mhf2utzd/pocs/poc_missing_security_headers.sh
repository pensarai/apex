#!/bin/bash

# POC: Missing Critical Security Headers
# This script tests for the presence of critical security headers

TARGET="http://localhost:8080"
ENDPOINTS=("/" "/login")

echo "========================================"
echo "POC: Missing Security Headers"
echo "Target: $TARGET"
echo "========================================"
echo ""

# Headers to check
HEADERS=(
    "X-Frame-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Content-Type-Options"
)

MISSING_COUNT=0
TOTAL_CHECKS=0

for ENDPOINT in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $ENDPOINT"
    echo "----------------------------------------"
    
    # Make request and capture headers
    RESPONSE=$(curl -s -I "${TARGET}${ENDPOINT}" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "Error: Could not connect to ${TARGET}${ENDPOINT}"
        echo ""
        continue
    fi
    
    # Check each security header
    for HEADER in "${HEADERS[@]}"; do
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        
        if echo "$RESPONSE" | grep -qi "^${HEADER}:"; then
            echo "✓ $HEADER: PRESENT"
        else
            echo "✗ $HEADER: MISSING"
            MISSING_COUNT=$((MISSING_COUNT + 1))
        fi
    done
    
    echo ""
done

echo "========================================"
echo "Summary:"
echo "Total header checks: $TOTAL_CHECKS"
echo "Missing headers: $MISSING_COUNT"
echo "========================================"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: $MISSING_COUNT critical security header(s) missing"
    echo ""
    echo "Impact:"
    echo "- Missing X-Frame-Options: Vulnerable to clickjacking attacks"
    echo "- Missing Content-Security-Policy: Vulnerable to XSS and code injection"
    echo "- Missing Strict-Transport-Security: Vulnerable to protocol downgrade attacks"
    echo "- Missing X-Content-Type-Options: Vulnerable to MIME-sniffing attacks"
    exit 0
else
    echo ""
    echo "All security headers are present."
    exit 1
fi