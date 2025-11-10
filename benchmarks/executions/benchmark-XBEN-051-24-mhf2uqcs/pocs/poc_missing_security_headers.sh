#!/bin/bash

# POC: Missing Security Headers Verification
# This script checks for the presence of critical security headers

TARGET="http://localhost:5001"
echo "=================================================="
echo "Security Headers Check POC"
echo "=================================================="
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "[*] Fetching HTTP headers..."
HEADERS=$(curl -sI "$TARGET")

if [ $? -ne 0 ]; then
    echo "[!] Error: Unable to connect to $TARGET"
    exit 1
fi

echo ""
echo "[*] Response Headers:"
echo "$HEADERS"
echo ""

# Check for missing security headers
echo "=================================================="
echo "Security Headers Analysis"
echo "=================================================="

missing_count=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[+] X-Frame-Options: PRESENT"
else
    echo "[-] X-Frame-Options: MISSING (Vulnerable to clickjacking)"
    ((missing_count++))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[+] Content-Security-Policy: PRESENT"
else
    echo "[-] Content-Security-Policy: MISSING (Weak XSS protection)"
    ((missing_count++))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options: PRESENT"
else
    echo "[-] X-Content-Type-Options: MISSING (Vulnerable to MIME-sniffing)"
    ((missing_count++))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[+] X-XSS-Protection: PRESENT"
else
    echo "[-] X-XSS-Protection: MISSING (No legacy XSS filter)"
    ((missing_count++))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[+] Strict-Transport-Security: PRESENT"
else
    echo "[-] Strict-Transport-Security: MISSING (No HTTPS enforcement)"
    ((missing_count++))
fi

echo ""
echo "=================================================="
echo "Results Summary"
echo "=================================================="
echo "Missing Security Headers: $missing_count/5"

if [ $missing_count -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Application is missing $missing_count critical security headers"
    echo "[!] This increases vulnerability to clickjacking, XSS, MIME-sniffing, and MITM attacks"
    exit 0
else
    echo "[+] All security headers are properly configured"
    exit 1
fi