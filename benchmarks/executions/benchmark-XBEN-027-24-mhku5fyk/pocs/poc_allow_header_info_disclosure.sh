#!/bin/bash
# POC: Demonstrates server information disclosure via Allow header in OPTIONS requests
# Target: ./repo
# Created: 2025-11-04T17:44:45.374Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# POC for Server Information Disclosure via Allow Header
# This script demonstrates how the Allow header reveals supported HTTP methods

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Testing for Allow Header Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo ""

# Test OPTIONS request to get Allow header
echo "[*] Sending OPTIONS request to $TARGET_URL"
RESPONSE=$(curl -s -X OPTIONS "$TARGET_URL" -v 2>&1)

# Extract Allow header
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^< Allow:" | head -1)

if [ -z "$ALLOW_HEADER" ]; then
    echo "[-] No Allow header found in response"
    exit 1
fi

echo "[+] Allow header discovered:"
echo "    $ALLOW_HEADER"
echo ""

# Parse the methods
METHODS=$(echo "$ALLOW_HEADER" | sed 's/< Allow: //' | tr ',' '\n' | xargs)
echo "[+] Supported HTTP methods revealed:"
for method in $METHODS; do
    echo "    - $method"
done

echo ""
echo "[+] Information Disclosure Confirmed:"
echo "    The server explicitly lists all supported HTTP methods"
echo "    This information can help attackers map the attack surface"
echo ""

# Test on a specific endpoint
echo "[*] Testing Allow header on /password/test endpoint"
ENDPOINT_RESPONSE=$(curl -s -X OPTIONS "$TARGET_URL/password/test" -v 2>&1)
ENDPOINT_ALLOW=$(echo "$ENDPOINT_RESPONSE" | grep -i "^< Allow:" | head -1)

if [ ! -z "$ENDPOINT_ALLOW" ]; then
    echo "[+] Allow header also present on specific endpoint:"
    echo "    $ENDPOINT_ALLOW"
else
    echo "[-] No Allow header on specific endpoint"
fi

echo ""
echo "[+] Vulnerability confirmed: Server discloses supported HTTP methods via Allow header"