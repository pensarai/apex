#!/bin/bash

# POC: Missing Security Headers
# This script checks for the presence of critical security headers in HTTP responses

TARGET_URL="${1:-http://localhost:5000/}"

echo "=========================================="
echo "Security Headers POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers
echo "Fetching HTTP headers from: $TARGET_URL"
RESPONSE=$(curl -i -s "$TARGET_URL" 2>/dev/null)

echo "Response Headers:"
echo "========================================"
echo "$RESPONSE" | head -20
echo ""

# Check for security headers
echo "Security Headers Analysis:"
echo "========================================"

declare -a HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Referrer-Policy"
    "X-Permitted-Cross-Domain-Policies"
    "Permissions-Policy"
)

MISSING_COUNT=0

for header in "${HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "Summary:"
echo "========================================"
echo "Security Headers Missing: $MISSING_COUNT/${#HEADERS[@]}"

# Check for Server header disclosure
echo ""
echo "Server Information Disclosure:"
echo "========================================"
if echo "$RESPONSE" | grep -qi "^Server:"; then
    SERVER_INFO=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d' ' -f2-)
    echo "✗ Server header present: $SERVER_INFO"
    echo "  (Reveals technology stack - information disclosure)"
else
    echo "✓ Server header not present"
fi

# Detailed vulnerability assessment
echo ""
echo "Vulnerability Assessment:"
echo "========================================"

if ! echo "$RESPONSE" | grep -qi "^X-Frame-Options:"; then
    echo "⚠ CLICKJACKING: Application vulnerable to clickjacking attacks"
fi

if ! echo "$RESPONSE" | grep -qi "^X-Content-Type-Options:"; then
    echo "⚠ MIME-SNIFFING: Application vulnerable to MIME-type sniffing"
fi

if ! echo "$RESPONSE" | grep -qi "^Content-Security-Policy:"; then
    echo "⚠ XSS: Application lacks CSP protection against XSS attacks"
fi

if ! echo "$RESPONSE" | grep -qi "^Strict-Transport-Security:"; then
    echo "⚠ MITM: Application lacks HSTS protection against man-in-the-middle"
fi

if ! echo "$RESPONSE" | grep -qi "^Referrer-Policy:"; then
    echo "⚠ REFERRER: Application may leak referrer information"
fi

if ! echo "$RESPONSE" | grep -qi "^Permissions-Policy:"; then
    echo "⚠ PERMISSIONS: Application doesn't restrict browser features"
fi

if [ $MISSING_COUNT -ge 5 ]; then
    echo ""
    echo "RESULT: VULNERABLE - Multiple critical security headers missing"
    exit 0
else
    echo ""
    echo "RESULT: Some security headers present"
    exit 0
fi