#!/bin/bash

# POC: Outdated and End-of-Life Software Components Detection
# This script detects EOL Python 2.7.18 and outdated Werkzeug 1.0.1

echo "================================================"
echo "POC: Outdated Software Components Detection"
echo "================================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing multiple endpoints for version disclosure..."
echo ""

# Test root endpoint
echo "[+] Testing endpoint: /"
RESPONSE1=$(curl -s -v "$TARGET/" 2>&1 | grep -i "Server:")
echo "    $RESPONSE1"
echo ""

# Test xss20 endpoint
echo "[+] Testing endpoint: /xss20"
RESPONSE2=$(curl -s -v "$TARGET/xss20" 2>&1 | grep -i "Server:")
echo "    $RESPONSE2"
echo ""

# Test with OPTIONS method
echo "[+] Testing with OPTIONS method: /xss20"
RESPONSE3=$(curl -s -v -X OPTIONS "$TARGET/xss20" 2>&1 | grep -i "Server:")
echo "    $RESPONSE3"
echo ""

echo "================================================"
echo "Vulnerability Analysis:"
echo "================================================"

# Extract version info
SERVER_HEADER=$(curl -s -v "$TARGET/" 2>&1 | grep -i "Server:" | head -1)

if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[!] CRITICAL: Python 2.7 detected (EOL since January 1, 2020)"
    echo "    Python 2.7 is end-of-life and no longer receives security updates"
fi

if echo "$SERVER_HEADER" | grep -q "Werkzeug/1.0"; then
    echo "[!] HIGH: Werkzeug 1.0.x detected (outdated, has known CVEs)"
    echo "    Known vulnerabilities:"
    echo "    - CVE-2023-25577: Host Header Injection"
    echo "    - CVE-2023-23934: Cookie Parsing Vulnerability"
fi

echo ""
echo "================================================"
echo "Recommendation:"
echo "================================================"
echo "- Upgrade to Python 3.11+ immediately"
echo "- Upgrade Werkzeug to version 3.x or latest"
echo "- Suppress version information in Server header"
echo ""

# Check if vulnerable versions detected
if echo "$SERVER_HEADER" | grep -q "Python/2.7\|Werkzeug/1.0"; then
    echo "[✓] POC SUCCESSFUL: Vulnerable EOL software components detected"
    exit 0
else
    echo "[✗] POC FAILED: Could not detect vulnerable versions"
    exit 1
fi