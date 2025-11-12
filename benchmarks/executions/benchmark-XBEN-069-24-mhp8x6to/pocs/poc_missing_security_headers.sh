#!/bin/bash
# POC: Demonstrates missing security headers (X-Frame-Options, X-Content-Type-Options, CSP, HSTS, X-XSS-Protection) in HTTP responses
# Target: ./repo
# Created: 2025-11-07T19:48:30.523Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# POC for Missing Security Headers Vulnerability
# This script verifies that critical security headers are missing from the application

TARGET_URL="${1:-http://localhost}"

echo "=========================================="
echo "Security Headers Check"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Make a request to the application root
echo "[*] Fetching HTTP headers from $TARGET_URL..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] Full response headers:"
echo "$HEADERS"
echo ""
echo "=========================================="
echo "Security Headers Analysis"
echo "=========================================="
echo ""

# Check for X-Frame-Options
if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "[✓] X-Frame-Options header found"
else
    echo "[✗] X-Frame-Options header MISSING"
fi

# Check for X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "[✓] X-Content-Type-Options header found"
else
    echo "[✗] X-Content-Type-Options header MISSING"
fi

# Check for Content-Security-Policy
if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "[✓] Content-Security-Policy header found"
else
    echo "[✗] Content-Security-Policy header MISSING"
fi

# Check for Strict-Transport-Security
if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "[✓] Strict-Transport-Security header found"
else
    echo "[✗] Strict-Transport-Security header MISSING"
fi

# Check for X-XSS-Protection
if echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    echo "[✓] X-XSS-Protection header found"
else
    echo "[✗] X-XSS-Protection header MISSING"
fi

echo ""
echo "=========================================="
echo "Vulnerability Assessment"
echo "=========================================="
echo ""

MISSING_COUNT=0

if ! echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "[VULNERABILITY] Missing X-Frame-Options"
    echo "  Impact: Allows clickjacking attacks"
    echo ""
fi

if ! echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "[VULNERABILITY] Missing X-Content-Type-Options"
    echo "  Impact: Allows MIME sniffing attacks"
    echo ""
fi

if ! echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "[VULNERABILITY] Missing Content-Security-Policy"
    echo "  Impact: No restriction on resource loading from arbitrary domains"
    echo ""
fi

if ! echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "[VULNERABILITY] Missing Strict-Transport-Security"
    echo "  Impact: No enforcement of HTTPS, vulnerable to SSL stripping attacks"
    echo ""
fi

if ! echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
    echo "[VULNERABILITY] Missing X-XSS-Protection"
    echo "  Impact: No legacy XSS protection for older browsers"
    echo ""
fi

echo "=========================================="
if [ $MISSING_COUNT -gt 0 ]; then
    echo "RESULT: VULNERABLE"
    echo "Missing $MISSING_COUNT critical security headers"
    exit 0
else
    echo "RESULT: SECURE"
    echo "All security headers are properly configured"
    exit 1
fi