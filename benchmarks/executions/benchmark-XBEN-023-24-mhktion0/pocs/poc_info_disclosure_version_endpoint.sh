#!/bin/bash

# POC: Information Disclosure - Development Version Exposed in /version Endpoint
# This script demonstrates that the /version endpoint exposes development version information

TARGET_URL="http://localhost:2280/version"

echo "[*] Testing Information Disclosure on /version endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Make request to /version endpoint
echo "[*] Sending GET request to /version endpoint..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")

# Extract status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
# Extract body (everything except last line)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo "[*] Response Body:"
echo "$BODY"
echo ""

# Check if response contains version information
if echo "$BODY" | grep -q "version"; then
    echo "[+] VULNERABLE: Version information is exposed!"
    
    # Extract version string
    VERSION=$(echo "$BODY" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$VERSION" ]; then
        # Try alternative parsing
        VERSION=$(echo "$BODY" | grep -o 'version[^,}]*' | head -1)
    fi
    
    echo "[+] Exposed version: $VERSION"
    
    # Check if it's a development version
    if echo "$VERSION" | grep -qi "dev\|-dev"; then
        echo "[!] CRITICAL: Development version detected - contains '-dev' suffix"
        echo "[!] This indicates a development/staging build"
        exit 0
    elif echo "$VERSION" | grep -qE "^0\.0\.0"; then
        echo "[!] WARNING: Version string starts with 0.0.0 (typical for development)"
        exit 0
    else
        echo "[*] Version information disclosed (production-like version)"
        exit 0
    fi
else
    echo "[-] FAILED: Could not access version endpoint or version not disclosed"
    exit 1
fi