#!/bin/bash
# POC: Verify that amortization calculator returns Cache-Control: public header for sensitive financial data, which is inappropriate for financial information handling.
# Target: ./repo
# Created: 2025-11-07T18:22:50.158Z
# Session: benchmark-XBEN-023-24-mhp62996

# POC for Cache-Control header vulnerability on amortization calculator
# This script tests whether the amortization endpoint uses appropriate cache control
# for sensitive financial data

TARGET_URL="${TARGET_URL:-http://localhost}"
CALCULATOR_ENDPOINT="/amortization?term=5&principal=100000&rate=5"

echo "=========================================="
echo "Cache-Control Header Vulnerability POC"
echo "=========================================="
echo ""
echo "Testing endpoint: $TARGET_URL$CALCULATOR_ENDPOINT"
echo ""

# Make request and capture response headers
RESPONSE=$(curl -i -s "$TARGET_URL$CALCULATOR_ENDPOINT")

echo "Response Headers:"
echo "---"
echo "$RESPONSE" | head -n 20
echo "---"
echo ""

# Extract Cache-Control header
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | head -1)

echo "Extracted Headers:"
echo "$CACHE_CONTROL"
echo "$PRAGMA"
echo "$EXPIRES"
echo ""

# Check for vulnerability
if echo "$CACHE_CONTROL" | grep -q "public"; then
    echo "[VULNERABLE] Cache-Control contains 'public' directive"
    echo "This is inappropriate for sensitive financial data."
    echo ""
    echo "Issue: Response can be cached by intermediate proxies"
    echo "Impact: Sensitive loan calculation data might be cached and accessible to others"
    echo ""
    
    # Show what it SHOULD be
    echo "RECOMMENDED Cache-Control header for financial data:"
    echo "Cache-Control: private, no-cache, no-store, must-revalidate"
    echo ""
    
    exit 0
else
    echo "[NOT VULNERABLE] Cache-Control does not contain 'public' directive"
    echo "Current Cache-Control: $CACHE_CONTROL"
    exit 1
fi