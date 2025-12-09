#!/bin/bash

# POC: Missing Cache-Control Headers on Sensitive Pages
# Tests for missing cache-control headers on the login endpoint
# which could allow caching of sensitive login pages

TARGET_URL="${1:-http://localhost:5003/login}"

echo "========================================="
echo "Cache-Control Headers Vulnerability POC"
echo "========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""
echo "Making HTTP request and analyzing response headers..."
echo ""

# Make request and capture headers
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "=== HTTP RESPONSE HEADERS ==="
echo "$RESPONSE" | head -20
echo ""

# Extract specific headers
echo "=== CACHE-RELATED HEADERS CHECK ==="
echo ""

# Check for Cache-Control header
CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" || true)
if [ -z "$CACHE_CONTROL" ]; then
    echo "Cache-Control: MISSING"
    CACHE_MISSING=1
else
    echo "Cache-Control: $CACHE_CONTROL"
    CACHE_MISSING=0
fi

# Check for Pragma header
PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" || true)
if [ -z "$PRAGMA" ]; then
    echo "Pragma: MISSING"
    PRAGMA_MISSING=1
else
    echo "Pragma: $PRAGMA"
    PRAGMA_MISSING=0
fi

# Check for Expires header
EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" || true)
if [ -z "$EXPIRES" ]; then
    echo "Expires: MISSING"
    EXPIRES_MISSING=1
else
    echo "Expires: $EXPIRES"
    EXPIRES_MISSING=0
fi

echo ""
echo "=== VULNERABILITY ASSESSMENT ==="
echo ""

# Check if all three headers are missing
if [ "$CACHE_MISSING" = "1" ] && [ "$PRAGMA_MISSING" = "1" ] && [ "$EXPIRES_MISSING" = "1" ]; then
    echo "[VULNERABLE] All cache control headers are missing!"
    echo "The login page is not protected against caching."
    echo ""
    echo "IMPACT:"
    echo "  - Browsers may cache the login form"
    echo "  - Intermediate proxies may cache sensitive content"
    echo "  - Unauthorized users on shared computers could access cached pages"
    echo "  - Cache poisoning attacks may be possible"
    echo ""
    echo "EXPECTED HEADERS (for sensitive pages):"
    echo "  Cache-Control: no-cache, no-store, must-revalidate, private"
    echo "  Pragma: no-cache"
    echo "  Expires: 0"
    echo ""
    exit 0
else
    if [ "$CACHE_MISSING" = "0" ]; then
        echo "[INFO] Cache-Control header is present"
    fi
    if [ "$PRAGMA_MISSING" = "0" ]; then
        echo "[INFO] Pragma header is present"
    fi
    if [ "$EXPIRES_MISSING" = "0" ]; then
        echo "[INFO] Expires header is present"
    fi
    echo ""
    echo "[NOT VULNERABLE] Adequate cache control headers are in place"
    exit 1
fi