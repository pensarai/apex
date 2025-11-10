#!/bin/bash

# POC: Missing Security Headers and Development Server Exposure
# Tests for absence of critical security headers and presence of version disclosure

TARGET_URL="http://localhost:5001"
TIMEOUT=5

echo "========================================"
echo "Security Headers Analysis POC"
echo "Target: $TARGET_URL"
echo "========================================"
echo ""

# Function to check if header is present
check_header() {
    local header_name="$1"
    local response="$2"
    
    if echo "$response" | grep -qi "^$header_name:"; then
        echo "[PRESENT] $header_name"
        return 0
    else
        echo "[MISSING] $header_name"
        return 1
    fi
}

# Perform HTTP request and capture headers
echo "Fetching HTTP response headers..."
echo ""

HTTP_RESPONSE=$(curl -i -s -m $TIMEOUT "$TARGET_URL" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "ERROR: Could not connect to $TARGET_URL"
    exit 1
fi

# Extract headers only (before blank line)
HEADERS=$(echo "$HTTP_RESPONSE" | head -n 20)

echo "Response Headers:"
echo "================="
echo "$HEADERS"
echo ""
echo "Security Headers Check:"
echo "======================="
echo ""

# Check for critical security headers
MISSING_COUNT=0

check_header "X-Frame-Options" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

check_header "X-XSS-Protection" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

check_header "X-Content-Type-Options" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

check_header "Strict-Transport-Security" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

check_header "Content-Security-Policy" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

check_header "Cache-Control" "$HEADERS"
[ $? -ne 0 ] && MISSING_COUNT=$((MISSING_COUNT + 1))

echo ""
echo "Server Version Disclosure Check:"
echo "==============================="

if echo "$HEADERS" | grep -qi "Server:.*Werkzeug"; then
    echo "[VULNERABLE] Server header discloses Werkzeug version:"
    echo "$HEADERS" | grep -i "Server:"
    VERSION_DISCLOSED=1
else
    echo "[OK] Server header not found or properly hidden"
    VERSION_DISCLOSED=0
fi

echo ""
echo "Protocol Check:"
echo "=============="
PROTOCOL=$(echo "$HTTP_RESPONSE" | head -n 1)
echo "$PROTOCOL"

if echo "$PROTOCOL" | grep -q "HTTP/1.0"; then
    echo "[VULNERABLE] HTTP/1.0 indicates development server"
else
    echo "[INFO] Using HTTP/1.1 or higher"
fi

echo ""
echo "========================================"
echo "Vulnerability Summary:"
echo "========================================"
echo "Missing Security Headers: $MISSING_COUNT/6"
echo "Server Version Disclosed: $VERSION_DISCLOSED"
echo ""

if [ $MISSING_COUNT -ge 3 ] && [ $VERSION_DISCLOSED -eq 1 ]; then
    echo "STATUS: VULNERABLE - Missing security headers and version disclosure detected"
    exit 0
else
    echo "STATUS: SECURE - Security headers properly configured"
    exit 1
fi