#!/bin/bash

# POC: Missing Security Headers Detection
# This script checks for the presence of critical HTTP security headers

TARGET_URL="${1:-http://localhost:8080/loan_details}"
COOKIE_FILE="/tmp/cookies.txt"

echo "========================================"
echo "Security Headers Vulnerability POC"
echo "========================================"
echo "Target: $TARGET_URL"
echo ""

# First, login to get a valid session
echo "[*] Logging in to get valid session..."
curl -s -c "$COOKIE_FILE" -d "username=test&password=test" http://localhost:8080/login > /dev/null 2>&1

# Fetch the page and capture headers
echo "[*] Fetching headers from target endpoint..."
HEADERS=$(curl -s -i -b "$COOKIE_FILE" "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "=================================="
echo "$HEADERS"
echo "=================================="
echo ""

# Check for each security header
echo "[*] Security Headers Analysis:"
echo ""

MISSING_COUNT=0

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: PRESENT"
    echo "$HEADERS" | grep -i "^X-Frame-Options:" | head -1
else
    echo "✗ X-Frame-Options: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
    echo "$HEADERS" | grep -i "^X-Content-Type-Options:" | head -1
else
    echo "✗ X-Content-Type-Options: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
    echo "$HEADERS" | grep -i "^X-XSS-Protection:" | head -1
else
    echo "✗ X-XSS-Protection: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
    echo "$HEADERS" | grep -i "^Content-Security-Policy:" | head -1
else
    echo "✗ Content-Security-Policy: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security: PRESENT"
    echo "$HEADERS" | grep -i "^Strict-Transport-Security:" | head -1
else
    echo "✗ Strict-Transport-Security: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

# Check Cache-Control for sensitive pages (should not be "public")
CACHE_CONTROL=$(echo "$HEADERS" | grep -i "^Cache-Control:" | head -1)
if echo "$CACHE_CONTROL" | grep -qi "public"; then
    echo "✗ Cache-Control: INSECURE (contains 'public' on sensitive page)"
    MISSING_COUNT=$((MISSING_COUNT + 1))
elif [ -z "$CACHE_CONTROL" ]; then
    echo "⚠ Cache-Control: Not properly configured"
else
    echo "✓ Cache-Control: Appears secure"
fi
echo "$CACHE_CONTROL"
echo ""

# Server header disclosure check
if echo "$HEADERS" | grep -qi "^Server:"; then
    echo "⚠ Server: INFORMATION DISCLOSURE"
    echo "$HEADERS" | grep -i "^Server:" | head -1
    MISSING_COUNT=$((MISSING_COUNT + 1))
else
    echo "✓ Server: Not disclosed"
fi
echo ""

echo "========================================"
echo "Summary: $MISSING_COUNT security issues found"
echo "========================================"

if [ $MISSING_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Application is missing critical security headers"
    exit 0
else
    echo "No security header issues detected"
    exit 1
fi