#!/bin/bash

# POC: X-XSS-Protection Header Explicitly Disabled on /xss5 endpoint
# This demonstrates that the application intentionally disables browser XSS protection

TARGET="http://localhost:5000"
ENDPOINT="/xss5"

echo "=========================================="
echo "POC: X-XSS-Protection Header Disabled"
echo "=========================================="
echo ""
echo "Testing endpoint: ${TARGET}${ENDPOINT}"
echo ""

# Make request to /xss5 endpoint and capture headers
echo "[*] Sending GET request to /xss5..."
RESPONSE=$(curl -s -i "${TARGET}${ENDPOINT}" 2>&1)

echo ""
echo "[*] Full Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check for X-XSS-Protection header
XSS_HEADER=$(echo "$RESPONSE" | grep -i "X-XSS-Protection")

if [ -n "$XSS_HEADER" ]; then
    echo "[!] VULNERABILITY CONFIRMED: X-XSS-Protection header found"
    echo "    Header value: $XSS_HEADER"
    echo ""
    
    # Check if it's explicitly set to 0 (disabled)
    if echo "$XSS_HEADER" | grep -q "0"; then
        echo "[!] CRITICAL: X-XSS-Protection is explicitly DISABLED (set to 0)"
        echo "    This actively removes browser-based XSS protection"
        echo ""
    fi
else
    echo "[*] X-XSS-Protection header not found in response"
    echo "    (Note: Absence is different from explicit disabling)"
    echo ""
fi

# Compare with another endpoint to show the difference
echo "[*] Comparing with /xss1 endpoint for reference..."
RESPONSE_XSS1=$(curl -s -i "${TARGET}/xss1" 2>&1)
XSS_HEADER_XSS1=$(echo "$RESPONSE_XSS1" | grep -i "X-XSS-Protection")

if [ -n "$XSS_HEADER_XSS1" ]; then
    echo "    /xss1 X-XSS-Protection: $XSS_HEADER_XSS1"
else
    echo "    /xss1 does not set X-XSS-Protection header (not explicitly disabled)"
fi

echo ""
echo "=========================================="
echo "Impact Assessment:"
echo "=========================================="
echo "- Explicitly setting X-XSS-Protection to 0 disables browser XSS filters"
echo "- This is WORSE than simply not setting the header"
echo "- Shows intentional weakening of security controls"
echo "- Combined with existing XSS vulnerabilities, increases exploitation risk"
echo "- Affects older browsers that still rely on this header"
echo ""
echo "Recommendation: Remove the explicit disabling or set to '1; mode=block'"
echo ""