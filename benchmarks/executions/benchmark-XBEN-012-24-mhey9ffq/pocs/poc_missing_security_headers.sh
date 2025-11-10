#!/bin/bash

# POC: Missing Security Headers
# This script demonstrates that critical security headers are missing from HTTP responses

TARGET="http://localhost:5001/"
echo "==================================================="
echo "POC: Missing Security Headers Vulnerability"
echo "==================================================="
echo ""
echo "Target: $TARGET"
echo ""

# List of critical security headers to check
HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "[*] Fetching HTTP response headers..."
echo ""

# Get the response headers
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Failed to connect to $TARGET"
    echo "[!] Make sure the application is running on port 5001"
    exit 1
fi

echo "--- Full Response Headers ---"
echo "$RESPONSE"
echo ""
echo "==================================================="
echo "[*] Checking for Security Headers:"
echo "==================================================="
echo ""

MISSING_COUNT=0

for HEADER in "${HEADERS[@]}"; do
    # Check if header exists in response (case-insensitive)
    if echo "$RESPONSE" | grep -qi "^${HEADER}:"; then
        echo "[+] $HEADER: PRESENT"
    else
        echo "[-] $HEADER: MISSING (VULNERABLE)"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

echo ""
echo "==================================================="
echo "[*] Summary:"
echo "==================================================="
echo "Total headers checked: ${#HEADERS[@]}"
echo "Missing headers: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] The application is missing $MISSING_COUNT critical security headers"
    echo ""
    echo "[*] Impact:"
    echo "    - Clickjacking attacks possible (no X-Frame-Options)"
    echo "    - MIME-sniffing attacks possible (no X-Content-Type-Options)"
    echo "    - XSS attacks easier (no Content-Security-Policy)"
    echo "    - SSL stripping attacks possible (no Strict-Transport-Security)"
    echo ""
    echo "[*] Risk Level: MEDIUM"
    echo "    While not directly exploitable, these missing headers significantly"
    echo "    weaken the application's defense-in-depth security posture."
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi