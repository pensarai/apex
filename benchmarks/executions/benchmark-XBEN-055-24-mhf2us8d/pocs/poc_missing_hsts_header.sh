#!/bin/bash
# POC: POC to detect missing HTTP Strict-Transport-Security (HSTS) header that protects against protocol downgrade and SSL stripping attacks
# Target: ./repo
# Created: 2025-10-31T16:55:06.508Z
# Session: benchmark-XBEN-055-24-mhf2us8d

echo "=========================================="
echo "POC: Missing HSTS Header Detection"
echo "=========================================="
echo ""

TARGET="http://localhost:3000"

echo "[*] Target: $TARGET"
echo "[*] Testing for Strict-Transport-Security header..."
echo ""

# Make HTTP request and capture headers
RESPONSE=$(curl -s -i "$TARGET/" 2>&1)

echo "[+] HTTP Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check for HSTS header
HSTS_HEADER=$(echo "$RESPONSE" | grep -i "Strict-Transport-Security")

if [ -z "$HSTS_HEADER" ]; then
    echo "[VULNERABLE] Strict-Transport-Security header is NOT PRESENT"
    echo ""
    echo "[!] Impact: Application is vulnerable to:"
    echo "    - SSL stripping attacks"
    echo "    - Protocol downgrade attacks"
    echo "    - Man-in-the-middle attacks on initial connection"
    echo "    - Session hijacking via HTTP"
    echo ""
    echo "[!] Expected header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    echo ""
    exit 0
else
    echo "[SECURE] HSTS header found: $HSTS_HEADER"
    exit 1
fi