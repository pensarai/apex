#!/bin/bash
# POC: Demonstrates Server header information disclosure revealing Werkzeug/3.1.3 Python/3.13.3 version information across multiple endpoints
# Target: ./repo
# Created: 2025-11-07T19:21:36.815Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# Server Header Information Disclosure POC
# This script demonstrates that the application discloses detailed server information
# through the Server header in HTTP responses across all endpoints

TARGET="http://localhost:8080"
ENDPOINTS=("/" "/check_service" "/nonexistent")
METHODS=("GET" "POST" "DELETE")

echo "========================================="
echo "Server Header Information Disclosure POC"
echo "========================================="
echo ""

vulnerable=0

# Test GET requests to various endpoints
echo "[*] Testing GET requests for Server header disclosure:"
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing GET $TARGET$endpoint"
    
    # Extract the Server header from response
    server_header=$(curl -s -i -X GET "$TARGET$endpoint" 2>&1 | grep -i "^Server:" | head -1)
    
    if [ -n "$server_header" ]; then
        echo "  ✓ VULNERABLE: $server_header"
        vulnerable=$((vulnerable + 1))
        
        # Check if it contains version information
        if echo "$server_header" | grep -qiE "Werkzeug|Python"; then
            echo "  ⚠ CRITICAL: Discloses framework and version information"
        fi
    else
        echo "  ✓ SECURE: No Server header found"
    fi
    echo ""
done

# Test POST requests
echo "[*] Testing POST request to /check_service for Server header:"
echo ""

server_header=$(curl -s -i -X POST "$TARGET/check_service" \
    -H "Content-Type: application/json" \
    -d '{"service_name":"test"}' 2>&1 | grep -i "^Server:" | head -1)

if [ -n "$server_header" ]; then
    echo "  ✓ VULNERABLE: $server_header"
    vulnerable=$((vulnerable + 1))
    echo "  ⚠ POST requests also disclose server information"
else
    echo "  ✓ SECURE: No Server header found"
fi
echo ""

# Check for security headers
echo "[*] Checking for protective security headers:"
echo ""

headers_to_check=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

response=$(curl -s -i "$TARGET/" 2>&1)

for header in "${headers_to_check[@]}"; do
    if echo "$response" | grep -qi "^$header:"; then
        echo "  ✓ PRESENT: $header"
    else
        echo "  ✗ MISSING: $header"
    fi
done

echo ""
echo "========================================="
echo "Summary: Found $vulnerable instances of Server header disclosure"
echo "========================================="
echo ""

# Exit with success if vulnerability is confirmed
if [ $vulnerable -gt 0 ]; then
    echo "CONCLUSION: Server information disclosure confirmed"
    exit 0
else
    echo "CONCLUSION: No Server header disclosure detected"
    exit 1
fi