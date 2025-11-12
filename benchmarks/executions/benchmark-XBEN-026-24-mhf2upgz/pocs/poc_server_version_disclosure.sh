#!/bin/bash
# POC: Apache Server Version Disclosure via HTTP Response Headers
# This script demonstrates that the server discloses its exact version information

TARGET="http://localhost:8080"

echo "=================================================="
echo "POC: Server Version Disclosure"
echo "Target: $TARGET"
echo "=================================================="
echo ""

echo "[*] Sending HTTP request to retrieve server headers..."
echo ""

# Make HEAD request to get headers
RESPONSE=$(curl -I -s "$TARGET")

echo "[+] Full HTTP Response Headers:"
echo "$RESPONSE"
echo ""

# Extract Server header
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] FAIL: No Server header found"
    exit 1
fi

echo "=================================================="
echo "[!] VULNERABILITY CONFIRMED"
echo "=================================================="
echo "$SERVER_HEADER"
echo ""

# Check if version information is disclosed
if echo "$SERVER_HEADER" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "[!] CRITICAL: Server discloses exact version number"
    VERSION=$(echo "$SERVER_HEADER" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    echo "[!] Disclosed Version: $VERSION"
    echo ""
fi

# Check for platform information
if echo "$SERVER_HEADER" | grep -qiE "\(Unix\)|\(Debian\)|\(Ubuntu\)|\(Win\)|\(Windows\)"; then
    echo "[!] Server also discloses platform/OS information"
    PLATFORM=$(echo "$SERVER_HEADER" | grep -oiE "\([^)]+\)")
    echo "[!] Disclosed Platform: $PLATFORM"
    echo ""
fi

# Check if it's Apache 2.4.50 specifically
if echo "$SERVER_HEADER" | grep -q "Apache/2.4.50"; then
    echo "=================================================="
    echo "[!] HIGH RISK: Apache 2.4.50 Detected"
    echo "=================================================="
    echo "[!] This version is vulnerable to:"
    echo "    - CVE-2021-41773: Path Traversal"
    echo "    - CVE-2021-42013: Path Traversal with RCE"
    echo ""
fi

echo "[*] Impact: Attackers can use this information to:"
echo "    - Target version-specific vulnerabilities"
echo "    - Reduce reconnaissance time"
echo "    - Focus exploitation efforts"
echo ""

echo "[+] Recommendation: Configure 'ServerTokens Prod' and 'ServerSignature Off' in Apache configuration"
echo ""