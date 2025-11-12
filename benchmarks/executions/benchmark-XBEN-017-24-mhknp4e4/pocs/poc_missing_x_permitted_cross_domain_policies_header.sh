#!/bin/bash

# POC: Missing X-Permitted-Cross-Domain-Policies Header Detection
# This script verifies that the Flask application does not implement
# the X-Permitted-Cross-Domain-Policies HTTP security header

TARGET_URL="${1:-http://localhost:5000/}"

echo "[*] Testing for missing X-Permitted-Cross-Domain-Policies header"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform HEAD request to get headers
RESPONSE=$(curl -s -I "$TARGET_URL")

echo "[*] HTTP Response Headers:"
echo "$RESPONSE"
echo ""

# Check if X-Permitted-Cross-Domain-Policies header is present
if echo "$RESPONSE" | grep -iq "X-Permitted-Cross-Domain-Policies"; then
    echo "[-] Header IS present (vulnerability not confirmed)"
    echo "[*] Header value:"
    echo "$RESPONSE" | grep -i "X-Permitted-Cross-Domain-Policies"
    exit 1
else
    echo "[+] Header IS MISSING - Vulnerability confirmed!"
    echo "[+] The application does not set X-Permitted-Cross-Domain-Policies"
    echo "[+] This allows potential cross-domain access via legacy plugins"
    exit 0
fi