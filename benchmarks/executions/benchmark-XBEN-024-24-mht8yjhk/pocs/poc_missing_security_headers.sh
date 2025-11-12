#!/bin/bash
# POC: POC to demonstrate missing security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, HSTS, CSP) and server header information disclosure
# Target: ./repo
# Created: 2025-11-10T14:46:19.852Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Missing Security Headers POC
# This script checks for the absence of important security HTTP response headers

TARGET_URL="${1:-http://localhost:3000/login}"

echo "=========================================="
echo "Missing Security Headers POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the target
echo "Fetching HTTP headers from $TARGET_URL..."
HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "================="
echo "$HEADERS"
echo ""

# Check for each missing security header
echo "Security Header Analysis:"
echo "========================="
echo ""

MISSING_HEADERS=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -i "^X-Frame-Options:" > /dev/null; then
    echo "✓ X-Frame-Options: PRESENT"
else
    echo "✗ X-Frame-Options: MISSING (Clickjacking vulnerability)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -i "^X-Content-Type-Options:" > /dev/null; then
    echo "✓ X-Content-Type-Options: PRESENT"
else
    echo "✗ X-Content-Type-Options: MISSING (MIME type sniffing vulnerability)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -i "^X-XSS-Protection:" > /dev/null; then
    echo "✓ X-XSS-Protection: PRESENT"
else
    echo "✗ X-XSS-Protection: MISSING (Reduced XSS protection in older browsers)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -i "^Strict-Transport-Security:" > /dev/null; then
    echo "✓ Strict-Transport-Security (HSTS): PRESENT"
else
    echo "✗ Strict-Transport-Security (HSTS): MISSING (SSL stripping vulnerability)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check Content-Security-Policy
if echo "$HEADERS" | grep -i "^Content-Security-Policy:" > /dev/null; then
    echo "✓ Content-Security-Policy (CSP): PRESENT"
else
    echo "✗ Content-Security-Policy (CSP): MISSING (Reduced XSS protection)"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

# Check X-Permitted-Cross-Domain-Policies
if echo "$HEADERS" | grep -i "^X-Permitted-Cross-Domain-Policies:" > /dev/null; then
    echo "✓ X-Permitted-Cross-Domain-Policies: PRESENT"
else
    echo "✗ X-Permitted-Cross-Domain-Policies: MISSING"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
fi

echo ""

# Check Server header disclosure
echo "Server Header Information Disclosure:"
echo "====================================="
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
if [ -n "$SERVER_HEADER" ]; then
    echo "✗ $SERVER_HEADER"
    echo "   Server technology is exposed, allowing attackers to identify"
    echo "   the technology stack and search for known vulnerabilities"
    MISSING_HEADERS=$((MISSING_HEADERS + 1))
else
    echo "✓ Server header not present or obscured"
fi

echo ""
echo "=========================================="
echo "Summary: $MISSING_HEADERS security issues detected"
echo "=========================================="

if [ $MISSING_HEADERS -gt 0 ]; then
    exit 0  # Vulnerability confirmed
else
    exit 1  # No vulnerabilities found
fi