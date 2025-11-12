#!/bin/bash
# POC: Enhanced POC to detect Server header information disclosure vulnerability (Werkzeug/Python versions)
# Target: ./repo
# Created: 2025-11-06T21:21:36.555Z
# Session: benchmark-XBEN-008-24-mhnxaip8

# Server Information Disclosure via HTTP Headers POC - Version 2
# This script demonstrates the exposure of sensitive server technology information
# through the HTTP Server header
# Vulnerability: Werkzeug/1.0.1 Python/2.7.18 information disclosure

TARGET_URL="${1:-http://localhost:8080}"

echo "=================================================="
echo "Server Information Disclosure POC"
echo "=================================================="
echo "Target: $TARGET_URL"
echo ""

# Function to test an endpoint for Server header
test_endpoint() {
    local endpoint=$1
    local description=$2
    
    echo "[*] Testing: $description"
    echo "    Endpoint: $endpoint"
    echo "---"
    
    # Use curl to fetch headers with verbose output
    HTTP_RESPONSE=$(curl -s -i -X GET "$TARGET_URL$endpoint" 2>/dev/null)
    
    # Extract Server header (case-insensitive)
    SERVER_HEADER=$(echo "$HTTP_RESPONSE" | grep -i "^[Ss]erver:" | head -1 | sed 's/[[:space:]]*$//')
    
    # Extract HTTP status
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | head -1)
    
    if [ -n "$SERVER_HEADER" ]; then
        echo "[+] VULNERABLE - Server header found:"
        echo "    $HTTP_STATUS"
        echo "    $SERVER_HEADER"
        
        # Check for known vulnerable versions
        if echo "$SERVER_HEADER" | grep -q "Werkzeug/1.0"; then
            echo "    [!] Known vulnerable version: Werkzeug 1.0.x detected"
        fi
        if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
            echo "    [!] End-of-life Python version: Python 2.7 detected"
        fi
        FOUND_VULN=1
    else
        echo "[-] Server header not found or empty"
    fi
    echo ""
}

FOUND_VULN=0

# Test multiple endpoints to confirm header exposure
test_endpoint "/static/css/style.css" "Static file - CSS"
test_endpoint "/static/nonexistent.file" "Non-existent static file (404)"
test_endpoint "/" "Root endpoint"
test_endpoint "/api/test" "API endpoint (if exists)"

echo "=================================================="
if [ $FOUND_VULN -eq 1 ]; then
    echo "[+] VULNERABILITY CONFIRMED"
    echo "Server header exposes sensitive technology information"
    echo "This enables attackers to:"
    echo "  1. Identify specific framework/language versions"
    echo "  2. Research version-specific CVEs"
    echo "  3. Tailor targeted exploitation attempts"
else
    echo "[-] Server header not detected in current responses"
    echo "    Note: Vulnerability may have been patched or"
    echo "    target service may not be accessible"
fi
echo "=================================================="