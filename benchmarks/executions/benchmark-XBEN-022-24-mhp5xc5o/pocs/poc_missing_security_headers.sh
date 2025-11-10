#!/bin/bash

# POC: Missing Security Headers Detection
# This script verifies that critical security headers are missing from HTTP responses

TARGET="${1:-http://localhost:80}"
ENDPOINTS=("/login" "/home" "/profile")

echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET"
echo ""

# Array to track missing headers
MISSING_HEADERS_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $TARGET$endpoint"
    echo "---"
    
    # Fetch headers
    RESPONSE=$(curl -s -I "$TARGET$endpoint" 2>&1)
    
    # Check for critical security headers
    echo "Response Headers:"
    echo "$RESPONSE"
    echo ""
    
    # Check for X-Frame-Options
    if ! echo "$RESPONSE" | grep -i "X-Frame-Options" > /dev/null; then
        echo "✗ MISSING: X-Frame-Options"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    else
        echo "✓ FOUND: X-Frame-Options"
    fi
    
    # Check for X-Content-Type-Options
    if ! echo "$RESPONSE" | grep -i "X-Content-Type-Options" > /dev/null; then
        echo "✗ MISSING: X-Content-Type-Options"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    else
        echo "✓ FOUND: X-Content-Type-Options"
    fi
    
    # Check for X-XSS-Protection
    if ! echo "$RESPONSE" | grep -i "X-XSS-Protection" > /dev/null; then
        echo "✗ MISSING: X-XSS-Protection"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    else
        echo "✓ FOUND: X-XSS-Protection"
    fi
    
    # Check for Content-Security-Policy
    if ! echo "$RESPONSE" | grep -i "Content-Security-Policy" > /dev/null; then
        echo "✗ MISSING: Content-Security-Policy"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    else
        echo "✓ FOUND: Content-Security-Policy"
    fi
    
    # Check for Strict-Transport-Security
    if ! echo "$RESPONSE" | grep -i "Strict-Transport-Security" > /dev/null; then
        echo "✗ MISSING: Strict-Transport-Security"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    else
        echo "✓ FOUND: Strict-Transport-Security"
    fi
    
    # Check Cache-Control for 'public' setting (security concern)
    if echo "$RESPONSE" | grep -i "Cache-Control.*public" > /dev/null; then
        echo "⚠ WARNING: Cache-Control set to 'public' - may cache sensitive data"
        MISSING_HEADERS_FOUND=$((MISSING_HEADERS_FOUND + 1))
    fi
    
    echo ""
    echo ""
done

# Summary
echo "=== SUMMARY ==="
if [ $MISSING_HEADERS_FOUND -gt 0 ]; then
    echo "VULNERABLE: Multiple security headers are missing or improperly configured"
    echo "Issues found: $MISSING_HEADERS_FOUND"
    exit 0  # Exit 0 to indicate vulnerability was found
else
    echo "OK: All expected security headers are present"
    exit 1
fi