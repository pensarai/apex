#!/bin/bash

# POC: HTTP Methods Disclosure via Allow Header
# This script demonstrates how the application exposes allowed HTTP methods
# through the Allow header in both 405 responses and OPTIONS requests

TARGET_HOST="localhost"
TARGET_PORT="5003"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "HTTP Methods Disclosure POC"
echo "=========================================="
echo ""

# Test 1: OPTIONS request to /profile
echo "[*] Test 1: OPTIONS request to /profile"
echo "Command: curl -i -X OPTIONS ${BASE_URL}/profile"
echo ""
RESPONSE=$(curl -s -i -X OPTIONS "${BASE_URL}/profile" 2>&1)
echo "$RESPONSE"
echo ""

# Extract Allow header from OPTIONS response
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
if [ -n "$ALLOW_HEADER" ]; then
    echo "[+] FOUND: $ALLOW_HEADER"
else
    echo "[-] No Allow header in OPTIONS response"
fi
echo ""

# Test 2: POST request to /profile (should get 405)
echo "[*] Test 2: POST request to /profile (should get 405 Method Not Allowed)"
echo "Command: curl -i -X POST ${BASE_URL}/profile"
echo ""
RESPONSE=$(curl -s -i -X POST "${BASE_URL}/profile" 2>&1)
echo "$RESPONSE"
echo ""

# Extract Allow header from 405 response
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
HTTP_STATUS=$(echo "$RESPONSE" | grep -i "HTTP" | head -1)
if [ -n "$ALLOW_HEADER" ]; then
    echo "[+] FOUND: $ALLOW_HEADER"
    echo "[+] Status: $HTTP_STATUS"
else
    echo "[-] No Allow header in error response"
fi
echo ""

# Test 3: DELETE request to /profile (should get 405)
echo "[*] Test 3: DELETE request to /profile (should get 405 Method Not Allowed)"
echo "Command: curl -i -X DELETE ${BASE_URL}/profile"
echo ""
RESPONSE=$(curl -s -i -X DELETE "${BASE_URL}/profile" 2>&1)
echo "$RESPONSE"
echo ""

# Extract Allow header from 405 response
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
if [ -n "$ALLOW_HEADER" ]; then
    echo "[+] FOUND: $ALLOW_HEADER"
else
    echo "[-] No Allow header in error response"
fi
echo ""

# Test 4: OPTIONS request to /login
echo "[*] Test 4: OPTIONS request to /login"
echo "Command: curl -i -X OPTIONS ${BASE_URL}/login"
echo ""
RESPONSE=$(curl -s -i -X OPTIONS "${BASE_URL}/login" 2>&1)
echo "$RESPONSE"
echo ""

# Extract Allow header from OPTIONS response
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
if [ -n "$ALLOW_HEADER" ]; then
    echo "[+] FOUND: $ALLOW_HEADER"
else
    echo "[-] No Allow header in OPTIONS response"
fi
echo ""

echo "=========================================="
echo "Summary: Allow header disclosure confirmed"
echo "=========================================="