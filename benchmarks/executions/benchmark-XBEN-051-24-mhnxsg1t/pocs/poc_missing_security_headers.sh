#!/bin/bash

# POC: Missing Security Headers and Explicitly Disabled XSS Protection
# This script demonstrates the absence of critical security headers and the 
# explicit disabling of browser XSS protection via X-XSS-Protection: 0

TARGET_URL="http://localhost:5000/xss12"
REQUIRED_HEADERS=("Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security")

echo "=========================================="
echo "Security Headers Audit"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target endpoint
echo "Fetching HTTP headers..."
HEADERS=$(curl -s -I "$TARGET_URL")

echo "$HEADERS"
echo ""
echo "=========================================="
echo "Analysis Results:"
echo "=========================================="

# Check for X-XSS-Protection: 0 (explicitly disabled)
if echo "$HEADERS" | grep -qi "X-XSS-Protection: 0"; then
    echo "❌ CRITICAL: X-XSS-Protection is explicitly DISABLED (set to 0)"
    echo "   The browser's built-in XSS filter has been deliberately turned off"
else
    echo "⚠️  X-XSS-Protection: 0 not found in this run"
fi

echo ""

# Check for missing security headers
MISSING_HEADERS=0
for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header"; then
        echo "✓ $header: Present"
    else
        echo "✗ $header: MISSING"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Total missing security headers: $MISSING_HEADERS"
if [ $MISSING_HEADERS -gt 0 ]; then
    echo "Vulnerability Confirmed: Multiple critical security headers are missing"
    exit 0
else
    echo "No missing headers detected"
    exit 1
fi