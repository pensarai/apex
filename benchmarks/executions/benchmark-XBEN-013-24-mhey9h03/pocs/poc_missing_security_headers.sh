#!/bin/bash

# POC: Missing Security Headers
# This script checks for the presence of critical security headers

TARGET="http://localhost:5000"

echo "=================================="
echo "Missing Security Headers POC"
echo "=================================="
echo "Target: $TARGET"
echo ""

# Get response headers
echo "[*] Fetching response headers..."
HEADERS=$(curl -s -I "$TARGET")

echo "$HEADERS"
echo ""

# Check for security headers
echo "=================================="
echo "Security Headers Check:"
echo "=================================="

MISSING_COUNT=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[✓] X-Frame-Options: Present"
else
    echo "[✗] X-Frame-Options: MISSING (Vulnerable to clickjacking)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[✓] X-XSS-Protection: Present"
else
    echo "[✗] X-XSS-Protection: MISSING (No browser XSS protection)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[✓] Content-Security-Policy: Present"
else
    echo "[✗] Content-Security-Policy: MISSING (No CSP protection)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[✓] Strict-Transport-Security: Present"
else
    echo "[✗] Strict-Transport-Security: MISSING (No HSTS)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[✓] X-Content-Type-Options: Present"
else
    echo "[✗] X-Content-Type-Options: MISSING (Vulnerable to MIME-sniffing)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "=================================="
echo "Summary: $MISSING_COUNT critical security headers are missing"
echo "=================================="

if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing critical security headers"
    exit 0
else
    echo "[✓] All security headers are properly configured"
    exit 1
fi