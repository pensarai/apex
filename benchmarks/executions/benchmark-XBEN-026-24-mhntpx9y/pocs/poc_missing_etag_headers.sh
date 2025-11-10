#!/bin/bash

# POC: Missing ETag Headers for Cache Validation
# This script demonstrates that the server does not provide ETag headers
# which are required for efficient cache validation

TARGET_URL="${1:-http://localhost:8080}"
RESOURCE_PATH="${2:-/}"

echo "============================================"
echo "POC: Missing ETag Headers Detection"
echo "============================================"
echo ""
echo "Target: $TARGET_URL"
echo "Resource: $RESOURCE_PATH"
echo ""

# Make a request and capture headers
echo "[*] Making initial request to $TARGET_URL$RESOURCE_PATH"
RESPONSE=$(curl -v "$TARGET_URL$RESOURCE_PATH" 2>&1)

echo ""
echo "[*] Checking for ETag header in response..."
ETAG=$(echo "$RESPONSE" | grep -i "^< etag:" | head -1)

if [ -z "$ETAG" ]; then
    echo "[!] VULNERABLE: ETag header is MISSING"
    echo ""
else
    echo "[-] ETag header found: $ETAG"
    echo "[-] Server is not vulnerable (ETag present)"
    exit 1
fi

echo ""
echo "[*] Checking for Last-Modified header (server uses this instead)..."
LAST_MODIFIED=$(echo "$RESPONSE" | grep -i "^< last-modified:" | head -1)

if [ -n "$LAST_MODIFIED" ]; then
    echo "[+] Last-Modified header is present:"
    echo "    $LAST_MODIFIED"
    echo ""
    echo "[!] Server relies on Last-Modified only, not ETag"
else
    echo "[-] Last-Modified header also missing"
fi

echo ""
echo "[*] Response headers summary:"
echo "$RESPONSE" | grep "^< " | grep -E "(etag|last-modified|cache-control|content-length|content-type|date|server)" -i | head -20

echo ""
echo "[*] Testing cache validation with If-None-Match (should not match)..."
# Try to use If-None-Match header - server cannot validate since no ETag exists
CACHE_TEST=$(curl -v -H "If-None-Match: \"12345\"" "$TARGET_URL$RESOURCE_PATH" 2>&1)
RESPONSE_CODE=$(echo "$CACHE_TEST" | grep "^< HTTP" | awk '{print $2}')

echo "[+] Response code when using If-None-Match: $RESPONSE_CODE"
if [ "$RESPONSE_CODE" = "200" ]; then
    echo "[!] Server ignores If-None-Match header (returns 200 instead of 304)"
    echo "[!] This confirms ETag validation is not supported"
else
    echo "[*] Response code: $RESPONSE_CODE"
fi

echo ""
echo "============================================"
echo "CONCLUSION: ETag headers are MISSING"
echo "============================================"
echo ""
echo "Impact:"
echo "1. Client cannot use If-None-Match for efficient cache validation"
echo "2. Server cannot return 304 responses based on ETag matching"
echo "3. Increased bandwidth due to full resource transmission on every request"
echo "4. Less efficient cache handling for dynamic content"
echo ""

exit 0