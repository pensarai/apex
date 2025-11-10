#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical security headers
# and demonstrates the vulnerability

TARGET_URL="${1:-http://localhost:5000/}"
echo "Testing security headers on: $TARGET_URL"
echo "=========================================="
echo ""

# Define required security headers
declare -a HEADERS=(
    "X-Frame-Options"
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
)

# Make HTTP request and capture headers
echo "Making HTTP request to $TARGET_URL"
echo ""

RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full HTTP Response Headers:"
echo "=========================================="
echo "$RESPONSE" | head -20
echo ""
echo "=========================================="
echo ""

# Check for missing headers
echo "Security Headers Analysis:"
echo "=========================================="

MISSING_COUNT=0
PRESENT_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^${header}:"; then
        echo "✓ PRESENT: $header"
        ((PRESENT_COUNT++))
    else
        echo "✗ MISSING: $header"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "  Present: $PRESENT_COUNT/${#HEADERS[@]}"
echo "  Missing: $MISSING_COUNT/${#HEADERS[@]}"
echo "=========================================="
echo ""

# Security Risk Assessment
if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Missing security headers detected!"
    echo ""
    echo "Missing Headers Analysis:"
    echo "----------------------------------------"
    
    if ! echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
        echo "• X-Frame-Options missing: Application is vulnerable to clickjacking"
    fi
    
    if ! echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
        echo "• CSP missing: No policy to prevent XSS and injection attacks"
    fi
    
    if ! echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
        echo "• X-Content-Type-Options missing: Vulnerable to MIME type sniffing"
    fi
    
    if ! echo "$RESPONSE" | grep -qi "^X-XSS-Protection:"; then
        echo "• X-XSS-Protection missing: No XSS filter header protection"
    fi
    
    if ! echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
        echo "• HSTS missing: Not enforcing HTTPS, vulnerable to MITM attacks"
    fi
    
    if ! echo "$RESPONSE" | grep -qi "^Referrer-Policy:"; then
        echo "• Referrer-Policy missing: Sensitive referrer information may leak"
    fi
    
    echo "----------------------------------------"
    exit 0  # POC successful - vulnerability confirmed
else
    echo "All security headers are present. No vulnerability detected."
    exit 1  # No vulnerability
fi