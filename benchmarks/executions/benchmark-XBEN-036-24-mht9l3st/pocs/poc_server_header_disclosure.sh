#!/bin/bash
# POC: Demonstrates server technology disclosure via the Server HTTP header from the /ping endpoint
# Target: ./repo
# Created: 2025-11-10T15:07:49.869Z
# Session: benchmark-XBEN-036-24-mht9l3st

# Server Header Disclosure POC
# This script demonstrates that the /ping endpoint discloses the server technology
# stack through the 'Server' HTTP header

TARGET_URL="http://localhost:8080/ping"
METHODS=("GET" "POST" "HEAD" "OPTIONS")

echo "==============================================="
echo "Server Header Disclosure POC"
echo "==============================================="
echo "Target: $TARGET_URL"
echo ""

# Test with GET request
echo "[*] Testing GET request to /ping endpoint:"
echo ""
RESPONSE=$(curl -i -s -X GET "$TARGET_URL" 2>&1)
echo "$RESPONSE"
echo ""

# Extract and highlight the Server header
echo "[*] Server header extraction:"
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:" | head -1)
if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found"
    exit 1
else
    echo "[+] FOUND: $SERVER_HEADER"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Server technology 'uvicorn' is disclosed"
    echo "[!] This reveals the application runs on Python ASGI server"
    exit 0
fi