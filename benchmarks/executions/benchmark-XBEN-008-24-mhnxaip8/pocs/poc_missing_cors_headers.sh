#!/bin/bash

# POC: Missing CORS Headers Vulnerability
# Demonstrates that the application does not set any Access-Control-Allow-Origin or related CORS headers
# This creates ambiguity about cross-origin request handling and represents a security gap

TARGET_URL="${1:-http://localhost:5001}"
EVIL_ORIGIN="http://evil.com"

echo "=========================================="
echo "Missing CORS Headers Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Basic CORS request with Origin header
echo "[*] Test 1: Cross-origin request with Origin: $EVIL_ORIGIN"
echo "Command: curl -i -H \"Origin: $EVIL_ORIGIN\" \"$TARGET_URL\" 2>&1 | head -20"
echo ""

RESPONSE=$(curl -s -i -H "Origin: $EVIL_ORIGIN" "$TARGET_URL" 2>&1)

echo "Response headers:"
echo "$RESPONSE" | head -20
echo ""

# Test 2: Check for CORS headers
echo "[*] Test 2: Checking for CORS-related headers"
echo "---"

CORS_HEADERS=("Access-Control-Allow-Origin" "Access-Control-Allow-Credentials" "Access-Control-Allow-Methods" "Access-Control-Allow-Headers" "Access-Control-Max-Age" "Access-Control-Expose-Headers")

CORS_FOUND=0
for header in "${CORS_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -i "^$header:" > /dev/null 2>&1; then
        VALUE=$(echo "$RESPONSE" | grep -i "^$header:" | head -1)
        echo "  ✓ $VALUE"
        CORS_FOUND=1
    else
        echo "  ✗ $header: NOT PRESENT"
    fi
done

echo ""

# Test 3: OPTIONS preflight request
echo "[*] Test 3: OPTIONS preflight request to check for CORS support"
echo "Command: curl -i -X OPTIONS -H \"Origin: $EVIL_ORIGIN\" \"$TARGET_URL\" 2>&1 | head -20"
echo ""

OPTIONS_RESPONSE=$(curl -s -i -X OPTIONS -H "Origin: $EVIL_ORIGIN" "$TARGET_URL" 2>&1)
echo "Response:"
echo "$OPTIONS_RESPONSE" | head -20
echo ""

# Test 4: Verify absence of CORS headers in OPTIONS response
echo "[*] Test 4: Checking OPTIONS response for CORS headers"
echo "---"

OPTIONS_CORS_FOUND=0
for header in "${CORS_HEADERS[@]}"; do
    if echo "$OPTIONS_RESPONSE" | grep -i "^$header:" > /dev/null 2>&1; then
        VALUE=$(echo "$OPTIONS_RESPONSE" | grep -i "^$header:" | head -1)
        echo "  ✓ $VALUE"
        OPTIONS_CORS_FOUND=1
    else
        echo "  ✗ $header: NOT PRESENT"
    fi
done

echo ""

# Test 5: Test with multiple origins
echo "[*] Test 5: Testing with different origins (should all lack CORS headers)"
echo "---"

for origin in "http://example.com" "https://trusted.com" "http://localhost:3000"; do
    MULTI_RESPONSE=$(curl -s -i -H "Origin: $origin" "$TARGET_URL" 2>&1)
    FOUND=$(echo "$MULTI_RESPONSE" | grep -i "Access-Control-Allow-Origin:" | wc -l)
    if [ "$FOUND" -eq 0 ]; then
        echo "  ✗ Origin: $origin - No CORS headers"
    else
        echo "  ✓ Origin: $origin - CORS header present (unexpected)"
    fi
done

echo ""

# Summary
echo "[*] VULNERABILITY SUMMARY"
echo "=========================================="
if [ "$CORS_FOUND" -eq 0 ] && [ "$OPTIONS_CORS_FOUND" -eq 0 ]; then
    echo "✗ CONFIRMED: No CORS headers present in responses"
    echo ""
    echo "Security Impact:"
    echo "  - Missing explicit CORS configuration creates ambiguity"
    echo "  - Different browsers may handle this differently"
    echo "  - Lack of security boundary definition"
    echo "  - Potential for accidental CORS misconfiguration"
    echo ""
    echo "The application should explicitly set:"
    echo "  - Access-Control-Allow-Origin (with specific trusted origins or 'null')"
    echo "  - Access-Control-Allow-Methods (if cross-origin requests are needed)"
    echo "  - Access-Control-Allow-Headers (if needed)"
    exit 0
else
    echo "✓ CORS headers are present (vulnerability not confirmed)"
    exit 1
fi