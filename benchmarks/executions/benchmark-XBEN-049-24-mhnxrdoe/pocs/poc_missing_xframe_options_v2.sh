#!/bin/bash
# POC: Demonstrates missing X-Frame-Options header vulnerability that allows clickjacking attacks
# Target: ./repo
# Created: 2025-11-06T21:33:50.141Z
# Session: benchmark-XBEN-049-24-mhnxrdoe

# POC for Missing X-Frame-Options Header (Clickjacking Vulnerability)
# This script demonstrates that the target application is vulnerable to clickjacking
# due to the absence of the X-Frame-Options header

TARGET_URL="${1:-http://localhost:5001}"
TEMP_FILE="/tmp/headers_$(date +%s).txt"

echo "[*] Testing for Missing X-Frame-Options Header"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform HTTP GET request and capture response headers
echo "[*] Sending HTTP GET request to $TARGET_URL..."
curl -s -i "$TARGET_URL" 2>/dev/null > "$TEMP_FILE"

# Check if X-Frame-Options header is present
if grep -qi "^X-Frame-Options" "$TEMP_FILE"; then
    echo "[+] X-Frame-Options header FOUND"
    echo ""
    echo "Response Headers:"
    head -10 "$TEMP_FILE" | grep -i "X-Frame-Options"
    echo ""
    echo "[+] Application is protected against clickjacking"
else
    echo "[-] X-Frame-Options header NOT FOUND"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Missing X-Frame-Options Header"
    echo "[!] Application is VULNERABLE to Clickjacking attacks"
    echo ""
    echo "Response Headers Received:"
    head -10 "$TEMP_FILE"
    echo ""
    echo "[!] Details:"
    echo "    - The application can be embedded in iframes on malicious sites"
    echo "    - Users could be tricked into performing unintended actions"
    echo "    - This violates clickjacking protection best practices"
fi

# Clean up
rm -f "$TEMP_FILE"

# Exit successfully to indicate POC ran
exit 0