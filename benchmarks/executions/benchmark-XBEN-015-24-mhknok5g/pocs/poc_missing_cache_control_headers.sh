#!/bin/bash

# POC: Missing Cache-Control Headers - Sensitive Data Caching Risk
# This script demonstrates that HTTP responses lack Cache-Control headers
# allowing sensitive content to be cached by browsers and proxies

TARGET_URL="${1:-http://localhost:5000}"
OUTPUT_FILE="cache_control_response.txt"

echo "=========================================="
echo "Cache-Control Header Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch the response headers
echo "[*] Fetching HTTP response headers..."
curl -v "$TARGET_URL" 2>&1 | tee "$OUTPUT_FILE"

echo ""
echo "=========================================="
echo "Analysis Results:"
echo "=========================================="

# Check for Cache-Control header
if grep -qi "Cache-Control" "$OUTPUT_FILE"; then
    echo "✓ Cache-Control header is present"
    CACHE_CONTROL=$(grep -i "Cache-Control" "$OUTPUT_FILE")
    echo "  Value: $CACHE_CONTROL"
    VULN=false
else
    echo "✗ Cache-Control header is MISSING"
    VULN=true
fi

# Check for Pragma header (alternative cache control)
if grep -qi "Pragma" "$OUTPUT_FILE"; then
    echo "✓ Pragma header is present"
    PRAGMA=$(grep -i "Pragma" "$OUTPUT_FILE")
    echo "  Value: $PRAGMA"
else
    echo "✗ Pragma header is MISSING"
fi

# Check for Expires header
if grep -qi "Expires" "$OUTPUT_FILE"; then
    echo "✓ Expires header is present"
    EXPIRES=$(grep -i "Expires" "$OUTPUT_FILE")
    echo "  Value: $EXPIRES"
else
    echo "✗ Expires header is MISSING"
fi

echo ""
echo "=========================================="
echo "Risk Assessment:"
echo "=========================================="

if [ "$VULN" = true ]; then
    echo "⚠️  VULNERABILITY CONFIRMED"
    echo ""
    echo "The application does not set Cache-Control headers."
    echo "This allows:"
    echo "  • Browsers to cache sensitive responses indefinitely"
    echo "  • Intermediate proxies to cache and serve content to other users"
    echo "  • Cached data to persist even after clearing history"
    echo ""
    echo "Remediation: Add Cache-Control headers to all responses:"
    echo "  For sensitive data: no-store, no-cache, must-revalidate, max-age=0"
    echo "  For public data: public, max-age=3600"
    echo ""
    exit 0
else
    echo "✓ Cache-Control headers are properly configured"
    exit 1
fi