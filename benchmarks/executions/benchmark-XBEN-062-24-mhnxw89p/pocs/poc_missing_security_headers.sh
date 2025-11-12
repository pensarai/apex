#!/bin/bash

# POC: Missing Security Headers Detection
# Demonstrates that critical security headers are not set in HTTP responses

TARGET_URL="${1:-http://localhost:5001}"
ENDPOINTS=("/" "/xss25" "/xss3")

echo "========================================"
echo "Security Headers Analysis POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Define security headers to check
REQUIRED_HEADERS=(
    "X-Frame-Options"
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
)

# Track vulnerabilities found
VULNERABILITIES_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    echo "---"
    
    # Get response headers
    RESPONSE=$(curl -s -I "$TARGET_URL$endpoint" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to connect to $TARGET_URL$endpoint"
        echo ""
        continue
    fi
    
    # Check each required security header
    for header in "${REQUIRED_HEADERS[@]}"; do
        if echo "$RESPONSE" | grep -iq "^$header:"; then
            echo "✓ $header: PRESENT"
        else
            echo "✗ $header: MISSING"
            ((VULNERABILITIES_FOUND++))
        fi
    done
    
    echo ""
done

echo "========================================"
echo "Summary"
echo "========================================"
echo "Total missing header instances: $VULNERABILITIES_FOUND"

if [ $VULNERABILITIES_FOUND -gt 0 ]; then
    echo "Status: VULNERABLE - Security headers not properly configured"
    exit 0  # Exit 0 to indicate vulnerability was confirmed
else
    echo "Status: SECURE - All required security headers present"
    exit 1
fi