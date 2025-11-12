#!/bin/bash

# POC: Missing Critical Security Headers
# This script verifies that critical security headers are missing from application responses

TARGET="http://localhost:32768"
ENDPOINT="/home"
OUTPUT_FILE="/tmp/headers_response.txt"

echo "[*] Testing for missing critical security headers"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Make request and capture headers
curl -i -s "$TARGET$ENDPOINT" > "$OUTPUT_FILE" 2>&1

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[-] Failed to connect to target"
    exit 1
fi

echo "[*] Response headers:"
echo "---"
head -20 "$OUTPUT_FILE"
echo "---"
echo ""

# Check for missing security headers
echo "[*] Security Header Analysis:"
echo ""

HEADERS_MISSING=0

# Check X-Frame-Options
if ! grep -qi "X-Frame-Options" "$OUTPUT_FILE"; then
    echo "[-] MISSING: X-Frame-Options (Clickjacking protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
else
    echo "[+] PRESENT: X-Frame-Options"
fi

# Check X-Content-Type-Options
if ! grep -qi "X-Content-Type-Options" "$OUTPUT_FILE"; then
    echo "[-] MISSING: X-Content-Type-Options (MIME type sniffing protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
else
    echo "[+] PRESENT: X-Content-Type-Options"
fi

# Check X-XSS-Protection
if ! grep -qi "X-XSS-Protection" "$OUTPUT_FILE"; then
    echo "[-] MISSING: X-XSS-Protection (Browser XSS protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
else
    echo "[+] PRESENT: X-XSS-Protection"
fi

# Check Strict-Transport-Security
if ! grep -qi "Strict-Transport-Security" "$OUTPUT_FILE"; then
    echo "[-] MISSING: Strict-Transport-Security (HTTPS enforcement)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
else
    echo "[+] PRESENT: Strict-Transport-Security"
fi

# Check Content-Security-Policy
if ! grep -qi "Content-Security-Policy" "$OUTPUT_FILE"; then
    echo "[-] MISSING: Content-Security-Policy (XSS and injection protection)"
    HEADERS_MISSING=$((HEADERS_MISSING + 1))
else
    echo "[+] PRESENT: Content-Security-Policy"
fi

echo ""
echo "[*] Summary: $HEADERS_MISSING critical security headers are missing"
echo ""

if [ $HEADERS_MISSING -ge 5 ]; then
    echo "[+] VULNERABILITY CONFIRMED: All 5 critical security headers are missing"
    rm -f "$OUTPUT_FILE"
    exit 0
elif [ $HEADERS_MISSING -gt 0 ]; then
    echo "[!] WARNING: $HEADERS_MISSING critical security headers are missing"
    rm -f "$OUTPUT_FILE"
    exit 0
else
    echo "[-] All critical security headers are present"
    rm -f "$OUTPUT_FILE"
    exit 1
fi