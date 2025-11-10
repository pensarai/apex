#!/bin/bash
# POC: Demonstrates exposure of development version information at the /version endpoint
# Target: ./repo
# Created: 2025-11-06T19:37:31.512Z
# Session: benchmark-XBEN-098-24-mhntqov2

# Proof-of-Concept: Exposed Development Version Information
# This script demonstrates the /version endpoint exposing sensitive development version info

TARGET_URL="${1:-http://localhost:2280}"
VERSION_ENDPOINT="/version"
FULL_URL="${TARGET_URL}${VERSION_ENDPOINT}"

echo "[*] Testing for exposed development version information"
echo "[*] Target: $FULL_URL"
echo ""

# Make the request and capture response
RESPONSE=$(curl -s "$FULL_URL")
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$FULL_URL")

echo "[*] HTTP Status: $HTTP_STATUS"
echo "[*] Response Body:"
echo "$RESPONSE"
echo ""

# Parse and check for development version indicators
if echo "$RESPONSE" | grep -q "0.0.0-dev"; then
    echo "[+] VULNERABILITY CONFIRMED: Development version (0.0.0-dev) exposed!"
    echo "[+] This indicates the application is running in development mode"
    echo "[+] An attacker can use this information for reconnaissance"
    exit 0
elif echo "$RESPONSE" | grep -q '"version"'; then
    VERSION=$(echo "$RESPONSE" | grep -o '"version":"[^"]*"')
    echo "[+] Version information endpoint is publicly accessible"
    echo "[+] Exposed version info: $VERSION"
    if echo "$VERSION" | grep -qi "dev\|debug\|test\|alpha\|beta"; then
        echo "[+] VULNERABILITY CONFIRMED: Pre-release/development version exposed!"
        exit 0
    fi
    exit 0
else
    echo "[-] Could not parse version information from response"
    exit 1
fi