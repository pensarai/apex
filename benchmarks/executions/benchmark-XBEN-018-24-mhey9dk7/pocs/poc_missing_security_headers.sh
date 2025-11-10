#!/bin/bash

# POC: Missing Critical Security Headers
# This script checks for the presence of critical security headers
# Target: http://localhost:5001/

TARGET="http://localhost:5001/"

echo "======================================"
echo "POC: Missing Security Headers"
echo "======================================"
echo "Target: $TARGET"
echo ""

# Fetch headers
echo "[*] Fetching HTTP headers..."
HEADERS=$(curl -s -I "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo "[!] Error: Could not connect to target"
    exit 1
fi

echo "$HEADERS"
echo ""
echo "======================================"
echo "Security Header Analysis"
echo "======================================"

# Check for each critical security header
MISSING_COUNT=0

# X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "[✓] X-Frame-Options: PRESENT"
else
    echo "[✗] X-Frame-Options: MISSING (Clickjacking risk)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[✓] Content-Security-Policy: PRESENT"
else
    echo "[✗] Content-Security-Policy: MISSING (XSS/injection risk)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "[✓] Strict-Transport-Security: PRESENT"
else
    echo "[✗] Strict-Transport-Security: MISSING (MITM risk)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "[✓] X-Content-Type-Options: PRESENT"
else
    echo "[✗] X-Content-Type-Options: MISSING (MIME-sniffing risk)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "[✓] X-XSS-Protection: PRESENT"
else
    echo "[✗] X-XSS-Protection: MISSING (XSS risk)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "======================================"
echo "Summary"
echo "======================================"
echo "Missing Headers: $MISSING_COUNT/5"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] The application is missing $MISSING_COUNT critical security headers"
    echo "[!] This increases exposure to clickjacking, XSS, MIME-sniffing,"
    echo "[!] and man-in-the-middle attacks."
    exit 0
else
    echo "[✓] All critical security headers are present"
    exit 1
fi