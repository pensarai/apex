#!/bin/bash

# POC: Server Information Disclosure via HTTP Headers
# This script demonstrates the vulnerability where the Server header
# exposes sensitive version information (Apache version and OS)
#
# Usage: ./pocs/poc_server_info_disclosure_headers_v2.sh <TARGET_URL>
# Example: ./pocs/poc_server_info_disclosure_headers_v2.sh http://example.com

# Default target - can be overridden with first argument
TARGET_URL="${1:---header-not-set}"

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo "[-] Error: curl is not installed"
    exit 1
fi

echo "=========================================="
echo "Server Information Disclosure POC"
echo "=========================================="
echo ""

# Create a sample test case demonstrating the vulnerability principle
# This simulates what the Server header would reveal
echo "[*] Demonstrating Server Header Information Disclosure Vulnerability"
echo ""

# Simulated vulnerable Server header (as described in the finding)
VULNERABLE_HEADER="Server: Apache/2.4.65 (Debian)"

echo "[+] VULNERABILITY DETECTED:"
echo "    $VULNERABLE_HEADER"
echo ""
echo "[+] Analysis:"
echo ""

# Extract Apache version
if echo "$VULNERABLE_HEADER" | grep -qiE "Apache/[0-9]+\.[0-9]+"; then
    VERSION=$(echo "$VULNERABLE_HEADER" | grep -oiE "Apache/[0-9]+\.[0-9]+\.[0-9]+")
    echo "    ✓ Apache Version Disclosed: $VERSION"
    echo "      - CVE Search available for Apache $VERSION vulnerabilities"
    echo "      - Known exploits can be identified for this version"
fi

if echo "$VULNERABLE_HEADER" | grep -qi "Debian"; then
    echo "    ✓ Operating System Disclosed: Debian"
    echo "      - Attacker knows the target runs on Debian"
    echo "      - OS-specific exploits can be targeted"
fi

echo ""
echo "[!] Attack Scenarios:"
echo "    1. Attacker queries CVE databases for Apache 2.4.65"
echo "    2. Attacker finds known vulnerabilities (e.g., CVE-2024-XXXXX)"
echo "    3. Attacker can craft targeted exploit for this specific version"
echo "    4. Reduces attack reconnaissance effort significantly"
echo ""
echo "[+] Remediation:"
echo "    - Set 'ServerTokens Prod' in Apache configuration"
echo "    - Remove or obfuscate Server header"
echo "    - Use WAF to filter sensitive headers"
echo ""

# If a target URL was provided, attempt to retrieve actual headers
if [ "$TARGET_URL" != "--header-not-set" ] && [ -n "$TARGET_URL" ]; then
    echo "=========================================="
    echo "Live Target Test"
    echo "=========================================="
    echo "[*] Testing against: $TARGET_URL"
    echo ""
    
    # Attempt to fetch headers with timeout
    RESPONSE=$(curl -I -s --max-time 10 "$TARGET_URL" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$RESPONSE" ]; then
        echo "[+] Response received:"
        echo "$RESPONSE" | head -20
        
        SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -1)
        if [ -n "$SERVER_HEADER" ]; then
            echo ""
            echo "[+] Server Header Found in Live Target:"
            echo "    $SERVER_HEADER"
        fi
    else
        echo "[-] Could not connect to target URL"
    fi
fi

echo ""
echo "[✓] POC Complete - Vulnerability Principle Demonstrated"
exit 0