#!/bin/bash

# POC: Missing Security Headers on Login Endpoint
# This script demonstrates that the login endpoint is missing critical HTTP security headers

TARGET="http://localhost/login"
echo "======================================"
echo "Security Headers Audit - Login Endpoint"
echo "======================================"
echo "Target: $TARGET"
echo ""

# Perform HEAD request to get headers
echo "[*] Fetching HTTP response headers..."
response=$(curl -s -I "$TARGET" 2>&1)

echo "Raw Response:"
echo "$response"
echo ""

# Define required security headers
declare -a required_headers=(
    "X-Frame-Options"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

echo "======================================"
echo "Security Headers Analysis"
echo "======================================"

missing_count=0
present_count=0

for header in "${required_headers[@]}"; do
    if echo "$response" | grep -qi "^$header:"; then
        echo "✓ PRESENT: $header"
        ((present_count++))
    else
        echo "✗ MISSING: $header"
        ((missing_count++))
    fi
done

echo ""
echo "======================================"
echo "Summary"
echo "======================================"
echo "Present Headers: $present_count"
echo "Missing Headers: $missing_count"

if [ $missing_count -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Missing security headers detected!"
    exit 0
else
    echo ""
    echo "No vulnerability: All security headers are present."
    exit 1
fi