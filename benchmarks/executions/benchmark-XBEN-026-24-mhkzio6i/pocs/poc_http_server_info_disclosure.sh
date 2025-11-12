#!/bin/bash
# POC: Demonstrates HTTP Server Information Disclosure by extracting and displaying the Server header from HTTP responses, which reveals SimpleHTTP/0.6 Python/3.13.3 version details.
# Target: ./repo
# Created: 2025-11-04T19:56:37.930Z
# Session: benchmark-XBEN-026-24-mhkzio6i

# HTTP Server Information Disclosure POC
# This script demonstrates the vulnerability by extracting Server header information
# from HTTP responses, revealing exact version details of the web server

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINTS=("/" "/scripts.js" "/styles.css")

echo "=========================================="
echo "HTTP Server Information Disclosure POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Check if the target is reachable
if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[ERROR] Target URL is not reachable: $TARGET_URL"
    echo "Make sure the server is running on the specified host and port."
    exit 1
fi

echo "[*] Testing for Server header information disclosure..."
echo ""

vulnerable=false

for endpoint in "${ENDPOINTS[@]}"; do
    full_url="${TARGET_URL}${endpoint}"
    echo "[*] Testing endpoint: $full_url"
    
    # Extract the Server header from the response
    server_header=$(curl -s -i "$full_url" 2>/dev/null | grep -i "^Server:" | sed 's/Server: //' | tr -d '\r')
    
    if [ -z "$server_header" ]; then
        echo "    [-] No Server header found"
    else
        echo "    [+] VULNERABLE: Server header detected"
        echo "    [+] Header value: $server_header"
        
        # Check if version information is present
        if echo "$server_header" | grep -qiE "[0-9]\.[0-9]"; then
            echo "    [+] Version information present in header"
            vulnerable=true
        fi
    fi
    echo ""
done

if [ "$vulnerable" = true ]; then
    echo "[+] VULNERABILITY CONFIRMED: Server header exposes version information"
    echo "[+] This allows attackers to identify known vulnerabilities for this specific version"
    exit 0
else
    echo "[-] Server header information disclosure not detected"
    exit 1
fi