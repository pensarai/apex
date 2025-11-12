#!/bin/bash

# POC: Missing X-Content-Type-Options Header - MIME Type Sniffing Vulnerability
# This script verifies that the X-Content-Type-Options header is absent from HTTP responses
# allowing browsers to sniff MIME types and potentially execute malicious content

TARGET="${1:-http://localhost:5001}"
ENDPOINT="/"

echo "========================================"
echo "X-Content-Type-Options Header Check POC"
echo "========================================"
echo "Target: $TARGET"
echo "Endpoint: $ENDPOINT"
echo ""

# Check if target is reachable
echo "[*] Testing connectivity to target..."
if ! curl -s -m 5 "$TARGET" > /dev/null 2>&1; then
    echo "[-] Error: Cannot reach target at $TARGET"
    exit 1
fi
echo "[+] Target is reachable"
echo ""

# Function to check header in response
check_header() {
    local method=$1
    local endpoint=$2
    
    echo "[*] Testing $method $endpoint..."
    
    # Get full headers
    response=$(curl -s -i -X "$method" "$TARGET$endpoint" 2>&1)
    
    # Check for X-Content-Type-Options header
    if echo "$response" | grep -qi "^X-Content-Type-Options"; then
        header_value=$(echo "$response" | grep -i "^X-Content-Type-Options" | cut -d' ' -f2- | tr -d '\r')
        echo "[+] X-Content-Type-Options header PRESENT: $header_value"
        return 0
    else
        echo "[-] X-Content-Type-Options header MISSING (VULNERABLE)"
        return 1
    fi
}

# Store results
vulnerability_found=0

# Test multiple HTTP methods
for method in GET HEAD OPTIONS; do
    check_header "$method" "$ENDPOINT"
    if [ $? -ne 0 ]; then
        vulnerability_found=1
    fi
    echo ""
done

# Display full response headers for verification
echo "[*] Full HTTP Response Headers:"
echo "---"
curl -s -i "$TARGET$ENDPOINT" | head -20
echo "---"
echo ""

# Summary
echo "[*] VULNERABILITY ASSESSMENT:"
if [ $vulnerability_found -eq 1 ]; then
    echo "[!] VULNERABLE: X-Content-Type-Options header is missing"
    echo "[!] Impact: Browser MIME type sniffing attacks are possible"
    echo "[!] Browsers may interpret content based on file content rather than Content-Type header"
    echo ""
    echo "[+] POC Confirmed: Missing header vulnerability detected"
    exit 0
else
    echo "[+] SECURE: X-Content-Type-Options header is properly set"
    exit 1
fi