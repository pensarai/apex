#!/bin/bash

# POC: Missing Cache-Control Headers on /ping Endpoint
# This script demonstrates that the /ping endpoint does not return proper Cache-Control headers

echo "============================================"
echo "Testing for Missing Cache-Control Headers"
echo "============================================"
echo ""

TARGET_URL="${TARGET_URL:-http://localhost:3000}"
ENDPOINT="/ping"

echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Fetch all headers from the endpoint
echo "[*] Fetching HTTP headers..."
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL$ENDPOINT" 2>&1)

echo "Full HTTP Response:"
echo "-------------------"
echo "$RESPONSE"
echo ""
echo "-------------------"
echo ""

# Extract headers (case-insensitive search)
echo "[*] Checking for cache-related headers..."
echo ""

# Check for Cache-Control header
if echo "$RESPONSE" | grep -qi "^Cache-Control:"; then
    CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)
    echo "[+] Found: $CACHE_CONTROL"
else
    echo "[-] MISSING: Cache-Control header"
fi

# Check for Pragma header
if echo "$RESPONSE" | grep -qi "^Pragma:"; then
    PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | head -1)
    echo "[+] Found: $PRAGMA"
else
    echo "[-] MISSING: Pragma header"
fi

# Check for Expires header
if echo "$RESPONSE" | grep -qi "^Expires:"; then
    EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | head -1)
    echo "[+] Found: $EXPIRES"
else
    echo "[-] MISSING: Expires header"
fi

# Check for ETag header
if echo "$RESPONSE" | grep -qi "^ETag:"; then
    ETAG=$(echo "$RESPONSE" | grep -i "^ETag:" | head -1)
    echo "[+] Found: $ETAG"
else
    echo "[-] MISSING: ETag header"
fi

# Check for Last-Modified header
if echo "$RESPONSE" | grep -qi "^Last-Modified:"; then
    LAST_MOD=$(echo "$RESPONSE" | grep -i "^Last-Modified:" | head -1)
    echo "[+] Found: $LAST_MOD"
else
    echo "[-] MISSING: Last-Modified header"
fi

echo ""
echo "[*] Summary: Response lacks proper cache control headers"
echo "[*] This allows browsers/proxies to cache responses unpredictably"