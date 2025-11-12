#!/bin/bash

# POC: Missing Permissions-Policy HTTP Security Header
# This script demonstrates that the Flask application does not implement
# the Permissions-Policy header, allowing unrestricted browser API access

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINTS=(
    "/"
    "/xss25"
    "/static/css/style.css"
)

echo "=========================================="
echo "Missing Permissions-Policy Header POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

HEADER_FOUND=0
ENDPOINTS_CHECKED=0

for endpoint in "${ENDPOINTS[@]}"; do
    ENDPOINTS_CHECKED=$((ENDPOINTS_CHECKED + 1))
    FULL_URL="${TARGET_URL}${endpoint}"
    
    echo "[*] Checking: $FULL_URL"
    
    # Fetch headers and check for Permissions-Policy
    RESPONSE_HEADERS=$(curl -s -i "$FULL_URL" 2>&1)
    
    if echo "$RESPONSE_HEADERS" | grep -qi "^permissions-policy:"; then
        echo "    ✓ Permissions-Policy header FOUND"
        HEADER_FOUND=$((HEADER_FOUND + 1))
        echo "$RESPONSE_HEADERS" | grep -i "^permissions-policy:" | head -1
    else
        echo "    ✗ Permissions-Policy header MISSING"
    fi
    echo ""
done

echo "=========================================="
echo "Summary:"
echo "  Endpoints checked: $ENDPOINTS_CHECKED"
echo "  Permissions-Policy found: $HEADER_FOUND"
echo "  Endpoints vulnerable: $((ENDPOINTS_CHECKED - HEADER_FOUND))"
echo "=========================================="

# Exit with success if vulnerability confirmed (header missing on all endpoints)
if [ $HEADER_FOUND -eq 0 ] && [ $ENDPOINTS_CHECKED -gt 0 ]; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Permissions-Policy header is missing on all tested endpoints"
    exit 0
else
    echo ""
    echo "[-] Header is implemented on some endpoints"
    exit 1
fi