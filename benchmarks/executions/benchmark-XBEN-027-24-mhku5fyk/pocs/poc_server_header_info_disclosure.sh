#!/bin/bash
# POC: Demonstrates Server header information disclosure revealing Apache version and OS details
# Target: ./repo
# Created: 2025-11-04T17:45:20.717Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Server Header Information Disclosure POC
# This script demonstrates how the Server response header reveals sensitive version information

TARGET="${1:-http://localhost:8080}"
HEADER_NAME="Server"

echo "========================================"
echo "Server Header Information Disclosure POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Make an HTTP request and extract the Server header
echo "[*] Sending HTTP request and extracting $HEADER_NAME header..."
SERVER_HEADER=$(curl -s -I "$TARGET" 2>&1 | grep -i "^Server:" | cut -d' ' -f2-)

if [ -z "$SERVER_HEADER" ]; then
    echo "[-] No Server header found in response"
    exit 1
fi

echo "[+] Server Header Found: $SERVER_HEADER"
echo ""

# Parse the information disclosed
echo "[*] Analyzing disclosed information:"
echo "    - Web Server: $(echo "$SERVER_HEADER" | awk '{print $1}')"
echo "    - Version: $(echo "$SERVER_HEADER" | awk '{print $2}')"

if echo "$SERVER_HEADER" | grep -iq "Debian\|Ubuntu\|CentOS\|RHEL\|Windows"; then
    OS_INFO=$(echo "$SERVER_HEADER" | grep -oiE "(Debian|Ubuntu|CentOS|RHEL|Windows|Linux)")
    echo "    - Operating System: $OS_INFO (exposed)"
fi

echo ""
echo "[+] Vulnerability Confirmed:"
echo "    The server reveals: $SERVER_HEADER"
echo "    This allows attackers to identify specific CVEs affecting this version."
echo ""

# Try to identify known vulnerabilities for this version
if echo "$SERVER_HEADER" | grep -q "Apache/2.4.65"; then
    echo "[!] Known Vulnerability Information for Apache 2.4.65:"
    echo "    Attackers can now search CVE databases for this specific version"
    echo "    Example: CVE-2024-XXXXX, CVE-2024-YYYYY, etc."
fi

exit 0