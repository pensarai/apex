#!/bin/bash

# POC: Missing Content Security Policy (CSP) Header Detection
# This script verifies that the application lacks CSP protection on multiple endpoints

TARGET_URL="http://localhost:8080"
ENDPOINTS=("/" "/index.php" "/about.php" "/contact.php" "/post.php")

echo "=========================================="
echo "CSP Header Detection POC"
echo "=========================================="
echo ""

CSP_FOUND=0
CSP_REPORT_FOUND=0
ENDPOINTS_TESTED=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: $TARGET_URL$endpoint"
    ENDPOINTS_TESTED=$((ENDPOINTS_TESTED + 1))
    
    # Make HTTP request and extract response headers
    RESPONSE=$(curl -s -I "$TARGET_URL$endpoint" 2>&1)
    
    # Check for Content-Security-Policy header
    if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
        echo "  ✓ CSP Header Found"
        CSP_FOUND=$((CSP_FOUND + 1))
    else
        echo "  ✗ CSP Header NOT Found"
    fi
    
    # Check for Content-Security-Policy-Report-Only header
    if echo "$RESPONSE" | grep -qi "^Content-Security-Policy-Report-Only:"; then
        echo "  ✓ CSP Report-Only Header Found"
        CSP_REPORT_FOUND=$((CSP_REPORT_FOUND + 1))
    else
        echo "  ✗ CSP Report-Only Header NOT Found"
    fi
    
    echo ""
done

echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total endpoints tested: $ENDPOINTS_TESTED"
echo "Endpoints with CSP header: $CSP_FOUND"
echo "Endpoints with CSP Report-Only header: $CSP_REPORT_FOUND"
echo "Endpoints WITHOUT CSP protection: $((ENDPOINTS_TESTED - CSP_FOUND - CSP_REPORT_FOUND))"
echo ""

# Exit with error if no CSP headers found on any endpoint
if [ $((CSP_FOUND + CSP_REPORT_FOUND)) -eq 0 ]; then
    echo "⚠ VULNERABILITY CONFIRMED: No CSP headers detected on any endpoint"
    exit 0
else
    echo "✓ CSP headers are present on some endpoints"
    exit 1
fi