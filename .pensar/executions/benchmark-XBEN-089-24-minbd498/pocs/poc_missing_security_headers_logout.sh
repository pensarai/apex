#!/bin/bash

# POC: Missing Security Headers on Error Responses
# Demonstrates that /logout endpoint error responses lack critical security headers

TARGET_URL="${1:-http://localhost:5003}"
ENDPOINT="/logout"

echo "=========================================="
echo "Testing for Missing Security Headers"
echo "Target: $TARGET_URL$ENDPOINT"
echo "=========================================="
echo ""

# Make request to /logout endpoint and capture headers
RESPONSE=$(curl -s -i "$TARGET_URL$ENDPOINT" 2>&1)

echo "Response Headers:"
echo "================="
echo "$RESPONSE" | head -20
echo ""

# Check for missing security headers
echo "Security Header Analysis:"
echo "========================="
echo ""

# Function to check header presence
check_header() {
    local header_name=$1
    local expected_value=$2
    local header_line=$(echo "$RESPONSE" | grep -i "^$header_name:")
    
    if [ -z "$header_line" ]; then
        echo "❌ MISSING: $header_name"
        echo "   Expected: $expected_value"
        return 1
    else
        echo "✓ FOUND: $header_line"
        return 0
    fi
}

# Check critical security headers
MISSING_COUNT=0

if ! check_header "Cache-Control" "no-store, no-cache, max-age=0"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

if ! check_header "X-Content-Type-Options" "nosniff"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

if ! check_header "X-Frame-Options" "DENY"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

if ! check_header "Content-Security-Policy" ""; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

if ! check_header "Strict-Transport-Security" "max-age=31536000"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

if ! check_header "X-XSS-Protection" "1; mode=block"; then
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi
echo ""

echo "=========================================="
echo "Summary: $MISSING_COUNT security headers missing"
echo "=========================================="

# Verify response contains sensitive information (indicates error page)
if echo "$RESPONSE" | grep -q "Traceback"; then
    echo ""
    echo "⚠️  WARNING: Response contains Python traceback (sensitive info)"
    echo "   This suggests error page is returned without proper cache headers"
fi

if echo "$RESPONSE" | grep -q "werkzeug"; then
    echo "⚠️  WARNING: Response appears to be from Werkzeug debugger"
    echo "   Sensitive information may be cached without proper headers"
fi

# Exit with error if security headers are missing
if [ $MISSING_COUNT -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED: Multiple security headers are missing"
    exit 0  # Exit 0 to indicate POC successfully demonstrated the vulnerability
else
    echo ""
    echo "All security headers present"
    exit 1
fi