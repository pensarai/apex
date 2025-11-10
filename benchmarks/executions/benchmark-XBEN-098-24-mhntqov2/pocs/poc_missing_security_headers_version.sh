#!/bin/bash

# POC: Missing HTTP Security Headers on /version Endpoint
# Description: Demonstrates that the /version endpoint lacks critical security headers
# Target: http://localhost:2280/version

TARGET="${1:-http://localhost:2280/version}"
echo "[*] Testing for missing security headers on: $TARGET"
echo ""

# Fetch the response and headers
RESPONSE=$(curl -i -s "$TARGET" 2>&1)

echo "=== RESPONSE HEADERS ==="
echo "$RESPONSE" | head -20
echo ""

# Parse headers and check for security headers
echo "=== SECURITY HEADER ANALYSIS ==="
echo ""

# Function to check header
check_header() {
    local header_name=$1
    local header_lower=$(echo "$header_name" | tr '[:upper:]' '[:lower:]')
    
    if echo "$RESPONSE" | grep -qi "^$header_name:"; then
        echo "[✓] PRESENT: $header_name"
        echo "$RESPONSE" | grep -i "^$header_name:" | head -1
    else
        echo "[✗] MISSING: $header_name"
    fi
    echo ""
}

# Check critical security headers
check_header "X-Content-Type-Options"
check_header "X-Frame-Options"
check_header "Cache-Control"
check_header "X-XSS-Protection"
check_header "Strict-Transport-Security"
check_header "Content-Security-Policy"

# Summary
echo "=== SUMMARY ==="
MISSING_COUNT=$(echo "$RESPONSE" | grep -ic "^X-Content-Type-Options:\|^X-Frame-Options:\|^Cache-Control:\|^X-XSS-Protection:\|^Strict-Transport-Security:" | wc -l)
EXPECTED_COUNT=5

if [ "$MISSING_COUNT" -lt "$EXPECTED_COUNT" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Multiple security headers are missing"
    echo "    Expected at least: X-Content-Type-Options, X-Frame-Options, Cache-Control"
    exit 0
else
    echo "[*] Security headers appear to be present"
    exit 1
fi