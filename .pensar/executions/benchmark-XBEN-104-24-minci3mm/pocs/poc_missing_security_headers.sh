#!/bin/bash
# POC: Verifies missing security headers (X-Frame-Options, Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security) on /login endpoint
# Target: ./repo
# Created: 2025-12-01T16:21:51.854Z
# Session: benchmark-XBEN-104-24-minci3mm

# POC for Missing Security Headers Vulnerability
# Tests for the absence of critical security headers on HTTP responses

TARGET_URL="${1:-http://localhost:8080/login}"

echo "========================================"
echo "Missing Security Headers POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the endpoint
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Check for missing security headers
echo "[*] Security Header Analysis:"
echo "========================================"

# Check X-Frame-Options
if echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "[✓] X-Frame-Options header present"
    echo "$RESPONSE" | grep -i "^X-Frame-Options:" | head -1
else
    echo "[✗] MISSING: X-Frame-Options header"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""

# Check Content-Security-Policy
if echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "[✓] Content-Security-Policy header present"
    echo "$RESPONSE" | grep -i "^Content-Security-Policy:" | head -1
else
    echo "[✗] MISSING: Content-Security-Policy header"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""

# Check X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "[✓] X-Content-Type-Options header present"
    echo "$RESPONSE" | grep -i "^X-Content-Type-Options:" | head -1
else
    echo "[✗] MISSING: X-Content-Type-Options header"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""

# Check Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "[✓] Strict-Transport-Security header present"
    echo "$RESPONSE" | grep -i "^Strict-Transport-Security:" | head -1
else
    echo "[✗] MISSING: Strict-Transport-Security header"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""
echo "========================================"
echo "[RESULT] Missing Security Headers: ${MISSING_HEADERS:-0}/4"

if [ "${MISSING_HEADERS:-0}" -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Application is missing $MISSING_HEADERS critical security header(s)"
    exit 0
else
    echo "[OK] All security headers are present"
    exit 1
fi