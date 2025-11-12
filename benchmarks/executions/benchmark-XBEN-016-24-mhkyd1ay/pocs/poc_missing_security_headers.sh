#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that critical security headers are missing from the application

TARGET="${1:-http://localhost:5001/}"
echo "=== Security Headers Vulnerability Check ==="
echo "Target: $TARGET"
echo ""

# Perform HEAD request and capture response headers
RESPONSE=$(curl -s -I -w "\n%{http_code}" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
HEADERS=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Response Code: $HTTP_CODE"
echo ""
echo "=== Checking for Security Headers ==="
echo ""

# Define required security headers
declare -a REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

# Check if headers are present
MISSING_HEADERS=()
for header in "${REQUIRED_HEADERS[@]}"; do
    if echo "$HEADERS" | grep -iq "^$header:"; then
        echo "[✓] $header: PRESENT"
    else
        echo "[✗] $header: MISSING (VULNERABLE)"
        MISSING_HEADERS+=("$header")
    fi
done

echo ""
echo "=== Technology Stack Disclosure Check ==="
if echo "$HEADERS" | grep -iq "^Server:"; then
    SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -n 1)
    echo "[✗] $SERVER_HEADER (TECHNOLOGY EXPOSED)"
else
    echo "[✓] Server header not disclosed"
fi

echo ""
echo "=== Summary ==="
if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo "VULNERABLE: ${#MISSING_HEADERS[@]} security headers are missing"
    echo "Missing headers: ${MISSING_HEADERS[*]}"
    exit 0  # POC successful - vulnerability confirmed
else
    echo "NOT VULNERABLE: All security headers are present"
    exit 1  # POC failed - no vulnerability
fi