#!/bin/bash

# POC: Unrestricted Access to Error Handler Endpoint
# This script demonstrates that the /error endpoint is publicly accessible
# without authentication and returns HTTP 500 with public caching headers

TARGET_URL="${1:-http://localhost}"
ERROR_ENDPOINT="${TARGET_URL}/error"

echo "============================================"
echo "Testing Unrestricted Access to Error Endpoint"
echo "============================================"
echo ""
echo "Target: ${ERROR_ENDPOINT}"
echo ""

# Test 1: Access without authentication
echo "[*] Test 1: Accessing /error endpoint without authentication..."
echo ""

RESPONSE=$(curl -v "${ERROR_ENDPOINT}" 2>&1)

# Extract status code
STATUS_CODE=$(echo "${RESPONSE}" | grep "< HTTP" | awk '{print $3}')
echo "[+] HTTP Status Code: ${STATUS_CODE}"
echo ""

# Check if endpoint is accessible (returns 500)
if echo "${RESPONSE}" | grep -q "< HTTP/1.1 500"; then
    echo "[✓] VULNERABLE: Endpoint returns HTTP 500 and is accessible without authentication"
else
    echo "[✗] Endpoint not responding with 500"
fi
echo ""

# Test 2: Check for public caching headers
echo "[*] Test 2: Checking for public caching headers..."
echo ""

if echo "${RESPONSE}" | grep -i "Cache-Control.*public"; then
    echo "[✓] VULNERABLE: Found 'public' in Cache-Control header"
    echo "${RESPONSE}" | grep -i "Cache-Control"
else
    echo "[✗] No public caching directive found"
fi
echo ""

# Test 3: Check for Server header information
echo "[*] Test 3: Checking Server header..."
echo ""

if echo "${RESPONSE}" | grep "< Server:"; then
    echo "[✓] Server information disclosed:"
    echo "${RESPONSE}" | grep "< Server:"
else
    echo "[✗] No Server header found"
fi
echo ""

# Test 4: Verify endpoint is accessible from unauthenticated context
echo "[*] Test 4: Verifying unauthenticated access..."
echo ""

UNAUTHENTICATED_RESPONSE=$(curl -s -w "\n%{http_code}" "${ERROR_ENDPOINT}" 2>&1)
HTTP_CODE=$(echo "${UNAUTHENTICATED_RESPONSE}" | tail -n1)

if [ "${HTTP_CODE}" = "500" ]; then
    echo "[✓] VULNERABLE: Endpoint accessible without authentication (HTTP ${HTTP_CODE})"
    echo ""
    echo "Response Headers:"
    curl -s -i "${ERROR_ENDPOINT}" 2>&1 | head -n 20
else
    echo "[✗] HTTP ${HTTP_CODE} - Unexpected response"
fi
echo ""

echo "============================================"
echo "POC Complete"
echo "============================================"