#!/bin/bash
# POC: Missing Security Headers
# This script checks for the presence of critical security headers

TARGET="http://localhost:8082/"
echo "=========================================="
echo "Security Headers Check POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to target"
    exit 1
fi

echo "$RESPONSE"
echo ""
echo "=========================================="
echo "Security Headers Analysis"
echo "=========================================="

# Check for security headers
MISSING_COUNT=0

echo "[*] Checking for X-Frame-Options..."
if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - Application vulnerable to clickjacking"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for X-Content-Type-Options..."
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - Application vulnerable to MIME-sniffing attacks"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for Content-Security-Policy..."
if echo "$RESPONSE" | grep -qi "Content-Security-Policy"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - No XSS/injection protection via CSP"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for X-XSS-Protection..."
if echo "$RESPONSE" | grep -qi "X-XSS-Protection"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - Browser XSS filter not enabled"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for Strict-Transport-Security..."
if echo "$RESPONSE" | grep -qi "Strict-Transport-Security"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - No HTTPS enforcement (HSTS)"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for Referrer-Policy..."
if echo "$RESPONSE" | grep -qi "Referrer-Policy"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - No referrer policy defined"
    ((MISSING_COUNT++))
fi

echo "[*] Checking for Permissions-Policy..."
if echo "$RESPONSE" | grep -qi "Permissions-Policy"; then
    echo "    [✓] PRESENT"
else
    echo "    [✗] MISSING - No permissions policy defined"
    ((MISSING_COUNT++))
fi

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total missing security headers: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] The application is missing critical security headers"
    echo "[!] This weakens the security posture against multiple attack vectors"
    exit 0
else
    echo "[✓] All security headers are present"
    exit 1
fi