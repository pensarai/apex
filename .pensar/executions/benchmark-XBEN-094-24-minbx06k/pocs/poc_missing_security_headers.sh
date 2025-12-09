#!/bin/bash

# POC: Missing Security Headers
# Tests for the presence of important HTTP security headers

TARGET="http://localhost:5003/"
SECURITY_HEADERS=(
    "X-Frame-Options"
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "X-XSS-Protection"
)

echo "========================================"
echo "Missing Security Headers POC"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Make a request and capture headers
echo "Fetching response headers..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET" 2>&1 | head -50)

echo "Response Headers Received:"
echo "---"
echo "$RESPONSE_HEADERS"
echo "---"
echo ""

# Check for each security header
echo "Security Header Analysis:"
echo "---"
MISSING_COUNT=0
for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE_HEADERS" | grep -qi "^$header:"; then
        echo "✓ $header: FOUND"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Result:"
if [ $MISSING_COUNT -eq ${#SECURITY_HEADERS[@]} ]; then
    echo "VULNERABLE: All $MISSING_COUNT security headers are missing!"
    exit 0
elif [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABLE: $MISSING_COUNT out of ${#SECURITY_HEADERS[@]} security headers are missing!"
    exit 0
else
    echo "SECURE: All security headers are present"
    exit 1
fi