#!/bin/bash

# POC: X-Powered-By Header Information Disclosure
# This script demonstrates how the X-Powered-By header reveals server technology (Next.js)
# to any client making HTTP requests

TARGET="http://localhost:3000/team"

echo "==============================================="
echo "X-Powered-By Header Information Disclosure POC"
echo "==============================================="
echo ""
echo "Target: $TARGET"
echo ""

# Make HTTP request and extract headers
echo "[*] Making HTTP GET request to /team endpoint..."
echo ""

# Use curl to get response headers and display X-Powered-By
RESPONSE=$(curl -i -s "$TARGET" 2>&1)

echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Extract X-Powered-By header specifically
XPOWEREDBY=$(echo "$RESPONSE" | grep -i "x-powered-by" | head -1)

if [ -z "$XPOWEREDBY" ]; then
    echo "[-] X-Powered-By header not found"
    exit 1
else
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "[+] $XPOWEREDBY"
    echo ""
    echo "[+] This header reveals the application is using: Next.js"
    echo "[+] Attackers can use this information to:"
    echo "    - Research known vulnerabilities in Next.js"
    echo "    - Conduct targeted reconnaissance"
    echo "    - Plan more targeted attacks"
    echo ""
    exit 0
fi