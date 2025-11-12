#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical HTTP security headers
# in the Next.js application running on localhost:3000

TARGET_URL="http://localhost:3000/"
echo "=== Missing Security Headers POC ==="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "[*] Fetching HTTP response headers..."
HEADERS=$(curl -s -I "$TARGET_URL")

echo "[*] Full response headers:"
echo "$HEADERS"
echo ""

# Check for critical security headers
echo "[*] Checking for critical security headers..."
echo ""

# Array of security headers to check
declare -A HEADERS_CHECK=(
    ["Content-Security-Policy"]="Restricts execution of scripts and resources"
    ["X-Frame-Options"]="Prevents clickjacking attacks"
    ["X-Content-Type-Options"]="Prevents MIME type sniffing"
    ["Strict-Transport-Security"]="Enforces HTTPS communication"
    ["X-XSS-Protection"]="Provides additional XSS protection"
)

MISSING_COUNT=0

for header in "${!HEADERS_CHECK[@]}"; do
    if echo "$HEADERS" | grep -q "^$header:"; then
        echo "✓ FOUND: $header"
        echo "  Purpose: ${HEADERS_CHECK[$header]}"
    else
        echo "✗ MISSING: $header"
        echo "  Purpose: ${HEADERS_CHECK[$header]}"
        ((MISSING_COUNT++))
    fi
    echo ""
done

# Detailed header analysis
echo "[*] Detailed Header Analysis:"
echo ""

# Check Content-Type header (present but may indicate vulnerability without X-Content-Type-Options)
CONTENT_TYPE=$(echo "$HEADERS" | grep -i "^Content-Type:" || echo "NOT_FOUND")
if [ "$CONTENT_TYPE" != "NOT_FOUND" ]; then
    echo "✓ Content-Type header found: $CONTENT_TYPE"
    echo "  ⚠ WARNING: Without X-Content-Type-Options: nosniff, browsers may sniff MIME types"
else
    echo "✗ Content-Type header not found"
fi
echo ""

# Verify vulnerability confirmation
echo "[*] Vulnerability Confirmation:"
if [ $MISSING_COUNT -ge 3 ]; then
    echo "✓ CONFIRMED: Application is missing $MISSING_COUNT critical security headers"
    echo "✓ VULNERABILITY CONFIRMED: Security headers misconfiguration detected"
    exit 0
else
    echo "✗ Could not confirm - some headers present"
    exit 1
fi