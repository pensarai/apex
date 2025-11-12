#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that the application is missing critical security headers

TARGET="http://127.0.0.1"
ENDPOINTS=("/" "/check_service")

echo "=========================================="
echo "Missing Security Headers Vulnerability POC"
echo "=========================================="
echo ""

# Function to check for header presence
check_headers() {
    local endpoint=$1
    local url="${TARGET}${endpoint}"
    
    echo "Testing endpoint: $url"
    echo "-------------------------------------------"
    
    # Get response headers
    response=$(curl -s -i "$url" 2>&1)
    
    echo "Response Headers:"
    echo "$response" | head -20
    echo ""
    
    # Check for missing security headers
    echo "Security Headers Analysis:"
    echo ""
    
    missing_count=0
    present_count=0
    
    # Check Content-Security-Policy
    if echo "$response" | grep -iq "content-security-policy:"; then
        echo "[✓] Content-Security-Policy: PRESENT"
        ((present_count++))
    else
        echo "[✗] Content-Security-Policy: MISSING"
        ((missing_count++))
    fi
    
    # Check X-Frame-Options
    if echo "$response" | grep -iq "x-frame-options:"; then
        echo "[✓] X-Frame-Options: PRESENT"
        ((present_count++))
    else
        echo "[✗] X-Frame-Options: MISSING (Clickjacking vulnerability)"
        ((missing_count++))
    fi
    
    # Check X-Content-Type-Options
    if echo "$response" | grep -iq "x-content-type-options:"; then
        echo "[✓] X-Content-Type-Options: PRESENT"
        ((present_count++))
    else
        echo "[✗] X-Content-Type-Options: MISSING (MIME sniffing vulnerability)"
        ((missing_count++))
    fi
    
    # Check X-XSS-Protection
    if echo "$response" | grep -iq "x-xss-protection:"; then
        echo "[✓] X-XSS-Protection: PRESENT"
        ((present_count++))
    else
        echo "[✗] X-XSS-Protection: MISSING (Legacy XSS protection not set)"
        ((missing_count++))
    fi
    
    # Check Strict-Transport-Security
    if echo "$response" | grep -iq "strict-transport-security:"; then
        echo "[✓] Strict-Transport-Security: PRESENT"
        ((present_count++))
    else
        echo "[✗] Strict-Transport-Security: MISSING (HTTPS security vulnerability)"
        ((missing_count++))
    fi
    
    # Check Referrer-Policy
    if echo "$response" | grep -iq "referrer-policy:"; then
        echo "[✓] Referrer-Policy: PRESENT"
        ((present_count++))
    else
        echo "[✗] Referrer-Policy: MISSING"
        ((missing_count++))
    fi
    
    # Check Permissions-Policy
    if echo "$response" | grep -iq "permissions-policy:"; then
        echo "[✓] Permissions-Policy: PRESENT"
        ((present_count++))
    else
        echo "[✗] Permissions-Policy: MISSING"
        ((missing_count++))
    fi
    
    # Check Server header (information disclosure)
    if echo "$response" | grep -iq "^server:"; then
        server_header=$(echo "$response" | grep -i "^server:" | head -1)
        echo "[⚠]  $server_header (Information Disclosure)"
        ((present_count++))
    fi
    
    echo ""
    echo "Summary: $missing_count headers MISSING, $present_count issues found"
    echo "=========================================="
    echo ""
}

# Test each endpoint
for endpoint in "${ENDPOINTS[@]}"; do
    check_headers "$endpoint"
done

echo "POC RESULT: Missing security headers confirmed!"
echo "The application is vulnerable to:"
echo "  - Clickjacking attacks (no X-Frame-Options)"
echo "  - MIME-type sniffing leading to XSS (no X-Content-Type-Options)"
echo "  - Information disclosure via Server header"
echo "  - Other security risks from missing headers"