#!/bin/bash

# POC: Missing Security Headers Detection
# This script demonstrates the absence of critical HTTP security headers
# that protect against clickjacking, MIME sniffing, XSS, and other attacks

TARGET="http://localhost:8080"
ENDPOINTS=("/" "/index.html" "/styles.css" "/scripts.js")

# Required security headers
REQUIRED_HEADERS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
)

echo "=== Missing Security Headers Vulnerability POC ==="
echo "Target: $TARGET"
echo "Testing for missing security headers across multiple endpoints..."
echo ""

MISSING_COUNT=0
FOUND_COUNT=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "--- Testing: $TARGET$endpoint ---"
    
    # Fetch headers using curl
    RESPONSE=$(curl -s -I "$TARGET$endpoint" 2>&1)
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Could not connect to $TARGET$endpoint"
        continue
    fi
    
    # Display all response headers
    echo "Response Headers:"
    echo "$RESPONSE" | head -20
    echo ""
    
    # Check for missing security headers
    echo "Security Headers Analysis:"
    for header in "${REQUIRED_HEADERS[@]}"; do
        if echo "$RESPONSE" | grep -qi "^$header:"; then
            echo "[FOUND]   $header"
            ((FOUND_COUNT++))
        else
            echo "[MISSING] $header"
            ((MISSING_COUNT++))
        fi
    done
    echo ""
done

echo "=== Summary ==="
echo "Security Headers Found: $FOUND_COUNT"
echo "Security Headers Missing: $MISSING_COUNT"

if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "[VULNERABILITY CONFIRMED] Critical security headers are missing!"
    echo "This exposes the application to:"
    echo "  - Clickjacking attacks (missing X-Frame-Options)"
    echo "  - MIME type sniffing attacks (missing X-Content-Type-Options)"
    echo "  - Cross-site scripting attacks (missing Content-Security-Policy)"
    echo "  - Man-in-the-middle attacks (missing Strict-Transport-Security)"
    echo "  - Referrer information leakage (missing Referrer-Policy)"
    exit 0
else
    echo ""
    echo "All required security headers are present."
    exit 1
fi