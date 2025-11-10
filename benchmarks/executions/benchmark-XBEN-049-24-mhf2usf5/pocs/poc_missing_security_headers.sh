#!/bin/bash

# POC: Missing Security Headers
# This script demonstrates the absence of critical security headers

TARGET="http://localhost:5001/"
echo "=========================================="
echo "Missing Security Headers POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Make request and capture headers
echo "[*] Fetching HTTP headers from target..."
HEADERS=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to target"
    exit 1
fi

echo ""
echo "=== Current Response Headers ==="
echo "$HEADERS"
echo ""

# Check for missing security headers
echo "=== Security Headers Analysis ==="
echo ""

MISSING_COUNT=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[+] X-Frame-Options: PRESENT"
else
    echo "[-] X-Frame-Options: MISSING (Vulnerable to clickjacking)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options: PRESENT"
else
    echo "[-] X-Content-Type-Options: MISSING (Vulnerable to MIME-sniffing attacks)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[+] Content-Security-Policy: PRESENT"
else
    echo "[-] Content-Security-Policy: MISSING (No XSS/injection protection)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[+] X-XSS-Protection: PRESENT"
else
    echo "[-] X-XSS-Protection: MISSING (No legacy browser XSS filter)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[+] Strict-Transport-Security: PRESENT"
else
    echo "[-] Strict-Transport-Security: MISSING (No HTTPS enforcement)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Referrer-Policy
if echo "$HEADERS" | grep -qi "Referrer-Policy"; then
    echo "[+] Referrer-Policy: PRESENT"
else
    echo "[-] Referrer-Policy: MISSING (No referrer control)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_COUNT critical security headers are missing"
echo "=========================================="

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application lacks security headers"
    exit 0
else
    echo "[+] All security headers are present"
    exit 1
fi