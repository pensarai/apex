#!/bin/bash

# POC: Missing Security Headers Vulnerability
# Demonstrates the absence of critical HTTP security headers
# Target: localhost:8080/index.php

TARGET_URL="http://localhost:8080/index.php"
TIMEOUT=5

echo "========================================="
echo "Missing Security Headers POC"
echo "========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make HTTP request and capture headers
echo "[*] Sending HTTP request to target..."
RESPONSE=$(curl -i -s -X POST "$TARGET_URL" \
  -d "username=test&password=test" \
  -m $TIMEOUT 2>/dev/null)

if [ -z "$RESPONSE" ]; then
    echo "[-] Error: Could not reach target server"
    exit 1
fi

echo "[+] Response received"
echo ""

# Extract headers only
HEADERS=$(echo "$RESPONSE" | head -n 100)

echo "=== HTTP Response Headers ==="
echo "$HEADERS"
echo ""

# Check for missing security headers
echo "=== Security Header Analysis ==="
echo ""

MISSING_HEADERS=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[+] X-Frame-Options: PRESENT"
else
    echo "[-] X-Frame-Options: MISSING (vulnerable to clickjacking)"
    ((MISSING_HEADERS++))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options: PRESENT"
else
    echo "[-] X-Content-Type-Options: MISSING (vulnerable to MIME sniffing)"
    ((MISSING_HEADERS++))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[+] X-XSS-Protection: PRESENT"
else
    echo "[-] X-XSS-Protection: MISSING (no legacy XSS protection)"
    ((MISSING_HEADERS++))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[+] Content-Security-Policy: PRESENT"
else
    echo "[-] Content-Security-Policy: MISSING (vulnerable to XSS and injection attacks)"
    ((MISSING_HEADERS++))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[+] Strict-Transport-Security: PRESENT"
else
    echo "[-] Strict-Transport-Security: MISSING (no HTTPS enforcement)"
    ((MISSING_HEADERS++))
fi

echo ""
echo "=== Summary ==="
echo "Total missing security headers: $MISSING_HEADERS/5"
echo ""

if [ $MISSING_HEADERS -ge 3 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing critical security headers"
    exit 0
else
    echo "[*] Some security headers present, but gaps remain"
    exit 0
fi