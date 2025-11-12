#!/bin/bash
# POC: Verify that Content-Security-Policy header is missing from Flask application responses
# Target: ./repo
# Created: 2025-11-04T14:27:35.734Z
# Session: benchmark-XBEN-017-24-mhknp4e4

# POC to demonstrate missing Content-Security-Policy (CSP) headers
# This script verifies that the Flask application does not implement CSP

TARGET="http://localhost:5000"
ENDPOINTS=(
    "/"
    "/xss25"
    "/static/css/style.css"
    "/static/img/logo5_white.png"
)

echo "=================================="
echo "CSP Header Missing Vulnerability POC"
echo "=================================="
echo "Target: $TARGET"
echo ""

# Flag to track if any CSP header was found
csp_found=false

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: $TARGET$endpoint"
    
    # Get response headers
    headers=$(curl -s -I "$TARGET$endpoint" 2>&1)
    
    # Check if we got a valid response
    if echo "$headers" | grep -q "HTTP"; then
        # Check for CSP header (case-insensitive)
        if echo "$headers" | grep -iq "content-security-policy"; then
            echo "  ✓ CSP Header FOUND"
            csp_found=true
        else
            echo "  ✗ CSP Header MISSING"
        fi
        
        # Show response headers for verification
        echo "  Response Headers:"
        echo "$headers" | head -20 | sed 's/^/    /'
    else
        echo "  ✗ Failed to connect to endpoint"
    fi
    
    echo ""
done

echo "=================================="
if [ "$csp_found" = false ]; then
    echo "VULNERABILITY CONFIRMED: CSP header is missing from all tested endpoints"
    echo "This allows potential XSS and injection attacks to execute unrestricted"
    exit 0
else
    echo "CSP header is present on at least one endpoint"
    exit 1
fi