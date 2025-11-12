#!/bin/bash

# POC: Missing Strict-Transport-Security (HSTS) Header
# This script demonstrates that the application does not set the HSTS header
# on its HTTP responses, leaving it vulnerable to SSL stripping attacks

TARGET_URL="${1:-http://localhost:8080}"

echo "=========================================="
echo "HSTS Header Verification POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Function to check for HSTS header
check_hsts() {
    local endpoint="$1"
    local full_url="${TARGET_URL}${endpoint}"
    
    echo "Checking endpoint: $endpoint"
    echo "URL: $full_url"
    
    # Make request and capture headers
    response_headers=$(curl -s -i -X GET "$full_url" 2>/dev/null | head -20)
    
    # Check for HSTS header (case-insensitive)
    if echo "$response_headers" | grep -iq "strict-transport-security"; then
        echo "✓ HSTS Header FOUND"
        echo "$response_headers" | grep -i "strict-transport-security"
    else
        echo "✗ HSTS Header MISSING"
    fi
    
    echo ""
}

# Test multiple endpoints
echo "Testing for HSTS header presence across endpoints:"
echo ""

check_hsts "/"
check_hsts "/dashboard"
check_hsts "/orders"
check_hsts "/logout"

# Final summary
echo "=========================================="
echo "VERIFICATION RESULT"
echo "=========================================="
echo "The application does not set the Strict-Transport-Security header."
echo "This means browsers will not be instructed to use HTTPS-only connections."
echo "The application is vulnerable to SSL stripping and MITM attacks."
echo ""
echo "Recommended Fix:"
echo "Set header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
echo "=========================================="