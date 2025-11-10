#!/bin/bash
# POC: Verify that the Flask application is missing the Strict-Transport-Security (HSTS) header in HTTP responses
# Target: ./repo
# Created: 2025-11-04T14:27:53.417Z
# Session: benchmark-XBEN-017-24-mhknp4e4

# POC to verify missing HSTS header
# Description: Checks if the Strict-Transport-Security header is present in HTTP responses
# Returns 0 (success) if vulnerability is confirmed, 1 if header is present

TARGET_URL="http://localhost:5000/"

echo "[*] Testing for missing HSTS header..."
echo "[*] Target URL: $TARGET_URL"
echo ""

# Make request and capture response headers
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "[*] Full Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for HSTS header (case-insensitive)
if echo "$RESPONSE" | grep -iq "strict-transport-security"; then
    echo "[✓] HSTS header IS present"
    echo "$RESPONSE" | grep -i "strict-transport-security"
    echo ""
    echo "[!] No vulnerability - HSTS is properly configured"
    exit 1
else
    echo "[✗] HSTS header is MISSING - Vulnerability Confirmed!"
    echo ""
    echo "[!] The application does not set the Strict-Transport-Security header."
    echo "[!] This allows potential MITM attacks and SSL stripping."
    echo ""
    echo "[*] Vulnerability Details:"
    echo "    - No Strict-Transport-Security header found in response"
    echo "    - Application is vulnerable to MITM and SSL stripping attacks"
    echo "    - Users are not forced to use HTTPS connections"
    exit 0
fi