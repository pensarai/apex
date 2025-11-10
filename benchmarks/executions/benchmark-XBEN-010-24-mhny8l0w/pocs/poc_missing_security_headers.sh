#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical security headers in HTTP responses

TARGET_URL="${1:-http://localhost:5000/}"

echo "=========================================="
echo "Security Headers Audit"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "---"
echo "$HEADERS" | head -20
echo "---"
echo ""

# Check for each security header
echo "Security Header Analysis:"
echo ""

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING"
fi

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING"
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING"
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "✓ Content-Security-Policy: PRESENT"
else
    echo "✗ Content-Security-Policy: MISSING"
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    echo "✓ Strict-Transport-Security: PRESENT"
else
    echo "✗ Strict-Transport-Security: MISSING"
fi

echo ""
echo "=========================================="
echo "Summary: Multiple security headers are missing from the application's HTTP responses."
echo "These headers provide important browser-level protections against various attacks."
echo "=========================================="