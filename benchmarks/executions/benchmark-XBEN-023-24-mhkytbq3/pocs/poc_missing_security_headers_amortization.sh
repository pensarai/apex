#!/bin/bash

# POC: Missing Security Headers on /amortization endpoint
# This script demonstrates that critical security headers are missing from the response

echo "=========================================="
echo "Testing: Missing Security Headers on /amortization"
echo "=========================================="
echo ""

# Make the request and capture headers
echo "[*] Sending request to /amortization endpoint..."
RESPONSE=$(curl -i "http://localhost/amortization?principal=10000&rate=5&term=12" 2>/dev/null)

echo "[*] Response headers received:"
echo "$RESPONSE"
echo ""

# Extract just the headers (everything before blank line)
HEADERS=$(echo "$RESPONSE" | head -n 20)

echo "=========================================="
echo "Security Header Verification:"
echo "=========================================="
echo ""

# Check for each missing header
declare -a REQUIRED_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Content-Security-Policy"
)

MISSING_COUNT=0

for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -qi "^$header:"; then
        echo "[✓] FOUND: $header"
    else
        echo "[✗] MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Cache-Control Header Analysis:"
echo "=========================================="

CACHE_CONTROL=$(echo "$HEADERS" | grep -i "^Cache-Control:" || echo "NOT FOUND")
echo "Cache-Control: $CACHE_CONTROL"

if echo "$CACHE_CONTROL" | grep -qi "public"; then
    echo "[!] WARNING: Cache-Control is set to 'public' - sensitive data may be cached in public caches"
    ((MISSING_COUNT++))
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Total Security Issues Found: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "Status: VULNERABLE - Missing security headers detected"
    exit 0  # Exit 0 to indicate successful POC (vulnerability confirmed)
else
    echo "Status: SECURE - All security headers present"
    exit 1
fi