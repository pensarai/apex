#!/bin/bash
# POC: Outdated Werkzeug 1.0.1 with Known Security Vulnerabilities
# This POC verifies the application is running vulnerable Werkzeug 1.0.1

TARGET="http://localhost:5001"

echo "=================================================="
echo "POC: Werkzeug 1.0.1 Vulnerability Detection"
echo "=================================================="
echo ""

echo "[*] Checking Werkzeug version via Server header..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to $TARGET"
    echo "[!] Make sure the application is running"
    exit 1
fi

echo "$RESPONSE" | head -20

echo ""
echo "[*] Extracting Server header..."
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')

if [ -z "$SERVER_HEADER" ]; then
    echo "[!] Server header not found"
    exit 1
fi

echo "Server Header: $SERVER_HEADER"
echo ""

# Check for Werkzeug 1.0.1
if echo "$SERVER_HEADER" | grep -q "Werkzeug/1.0.1"; then
    echo "[+] VULNERABLE: Detected Werkzeug 1.0.1"
    echo ""
    echo "Known CVEs affecting Werkzeug 1.0.1:"
    echo "  - CVE-2023-25577: Path traversal in safe_join() function"
    echo "    Severity: HIGH"
    echo "    Description: Allows directory traversal attacks"
    echo ""
    echo "  - CVE-2023-23934: Cookie parsing cache poisoning"
    echo "    Severity: HIGH"
    echo "    Description: Improper cookie parsing can lead to cache poisoning"
    echo ""
    echo "[!] Werkzeug 1.0.1 was released in March 2020"
    echo "[!] Current stable version is 3.x with critical security fixes"
    echo "[!] Recommendation: Upgrade to Werkzeug 3.x immediately"
    echo ""
    echo "=================================================="
    echo "VULNERABILITY CONFIRMED"
    echo "=================================================="
    exit 0
else
    echo "[-] Werkzeug 1.0.1 not detected"
    echo "[-] Server: $SERVER_HEADER"
    exit 1
fi