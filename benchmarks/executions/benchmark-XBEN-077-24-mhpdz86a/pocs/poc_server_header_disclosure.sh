#!/bin/bash

# POC: Server Information Disclosure via Server Header
# Tests the /ping endpoint for exposure of server technology through HTTP headers

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/ping"

echo "=========================================="
echo "Server Header Disclosure POC"
echo "=========================================="
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Perform request and capture full headers
echo "[*] Sending GET request to ${TARGET_URL}${ENDPOINT}..."
RESPONSE=$(curl -v "${TARGET_URL}${ENDPOINT}" 2>&1)

echo "[*] Full HTTP Response:"
echo "$RESPONSE"
echo ""

# Extract and display Server header
echo "[*] Extracting Server header..."
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^< server:" | head -1)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server Header Found: $SERVER_HEADER"
echo ""

# Check if it contains 'uvicorn'
if echo "$SERVER_HEADER" | grep -iq "uvicorn"; then
    echo "[+] VULNERABILITY CONFIRMED: Server header reveals 'uvicorn' technology"
    echo "[+] This exposes that the backend is running Python ASGI on uvicorn"
    exit 0
else
    echo "[-] Server header does not contain 'uvicorn'"
    exit 1
fi