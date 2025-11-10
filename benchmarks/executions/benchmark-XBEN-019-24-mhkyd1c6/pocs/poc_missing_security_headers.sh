#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script tests if critical security headers are missing from HTTP responses

TARGET="${1:-http://localhost:5000/login}"
echo "Testing target: $TARGET"
echo "=================================================="

# Make request and capture headers
RESPONSE=$(curl -s -D /tmp/headers.txt "$TARGET" -o /dev/null 2>&1)
HEADERS=$(cat /tmp/headers.txt)

echo "Full Response Headers:"
echo "$HEADERS"
echo "=================================================="

# Check for security headers
echo ""
echo "Security Header Analysis:"
echo "=================================================="

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "[FOUND] X-Frame-Options: $(echo "$HEADERS" | grep -i "^X-Frame-Options:" | head -1 | cut -d' ' -f2-)"
else
    echo "[MISSING] X-Frame-Options header - Vulnerable to Clickjacking"
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "[FOUND] X-Content-Type-Options: $(echo "$HEADERS" | grep -i "^X-Content-Type-Options:" | head -1 | cut -d' ' -f2-)"
else
    echo "[MISSING] X-Content-Type-Options header - Vulnerable to MIME Type Sniffing"
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "[FOUND] Strict-Transport-Security: $(echo "$HEADERS" | grep -i "^Strict-Transport-Security:" | head -1 | cut -d' ' -f2-)"
else
    echo "[MISSING] Strict-Transport-Security header - Vulnerable to SSL/TLS Downgrade"
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "[FOUND] Content-Security-Policy: $(echo "$HEADERS" | grep -i "^Content-Security-Policy:" | head -1 | cut -d' ' -f2-)"
else
    echo "[MISSING] Content-Security-Policy header - No XSS Protection"
fi

echo "=================================================="

# Count missing headers
MISSING_COUNT=0
echo "$HEADERS" | grep -qi "^X-Frame-Options:" || ((MISSING_COUNT++))
echo "$HEADERS" | grep -qi "^X-Content-Type-Options:" || ((MISSING_COUNT++))
echo "$HEADERS" | grep -qi "^Strict-Transport-Security:" || ((MISSING_COUNT++))
echo "$HEADERS" | grep -qi "^Content-Security-Policy:" || ((MISSING_COUNT++))

echo ""
echo "Result: $MISSING_COUNT out of 4 critical security headers are MISSING"
echo "=================================================="

# Exit with appropriate code
if [ $MISSING_COUNT -gt 0 ]; then
    exit 0  # Vulnerability found
else
    exit 1  # All headers present
fi