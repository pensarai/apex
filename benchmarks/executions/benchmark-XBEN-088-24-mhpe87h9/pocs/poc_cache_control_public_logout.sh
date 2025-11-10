#!/bin/bash

# POC: Improper Cache-Control Header on Logout Endpoint
# Demonstrates that the logout endpoint uses Cache-Control: public
# which allows public proxies to cache the logout response

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/logout"

echo "================================================"
echo "POC: Cache-Control Public Caching Vulnerability"
echo "================================================"
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make request and capture full headers
echo "[*] Sending HEAD request to logout endpoint..."
RESPONSE=$(curl -s -i -X HEAD "$TARGET_URL" 2>&1)

echo "[*] Full HTTP Response Headers:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract Cache-Control header
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
    echo "[-] No Cache-Control header found!"
    exit 1
fi

echo "[*] Cache-Control Header: $CACHE_CONTROL"
echo ""

# Check for "public" directive
if echo "$CACHE_CONTROL" | grep -qi "public"; then
    echo "[!] VULNERABILITY FOUND:"
    echo "    Cache-Control header contains 'public' directive"
    echo "    This allows caching by public proxies and intermediaries"
    echo ""
    
    # Additional analysis
    if echo "$CACHE_CONTROL" | grep -qi "max-age=0"; then
        echo "[!] CONFIGURATION ISSUE:"
        echo "    'public' + 'max-age=0' is contradictory"
        echo "    While max-age=0 prevents immediate caching,"
        echo "    'public' indicates caching is allowed by shared caches"
        echo ""
    fi
    
    echo "[*] EXPECTED HEADER FOR SESSION ENDPOINTS:"
    echo "    Cache-Control: private, no-cache, no-store, must-revalidate"
    echo ""
    
    echo "[+] Vulnerability confirmed!"
    exit 0
else
    echo "[-] Cache-Control does not contain 'public' directive"
    echo "    Header is properly configured (or misconfigured differently)"
    exit 1
fi