#!/bin/bash

# POC: Missing Cache-Control Headers
# This script demonstrates that the Flask application is missing proper Cache-Control headers
# on the main page, allowing sensitive content to be cached by browsers and intermediary caches.

TARGET_URL="http://localhost:5001"

echo "=========================================="
echo "POC: Missing Cache-Control Headers"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch headers from the main page
echo "[*] Fetching HTTP headers from main page..."
echo ""

RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

echo "=== FULL RESPONSE HEADERS ==="
echo "$RESPONSE" | grep -E "^(<|>)" | head -30
echo ""

# Check for Cache-Control header
echo "=== CACHE CONTROL ANALYSIS ==="
if echo "$RESPONSE" | grep -iq "Cache-Control:"; then
    echo "[+] Cache-Control header found:"
    echo "$RESPONSE" | grep -i "Cache-Control:"
else
    echo "[-] MISSING: Cache-Control header"
fi

echo ""

# Check for Expires header
if echo "$RESPONSE" | grep -iq "Expires:"; then
    echo "[+] Expires header found:"
    echo "$RESPONSE" | grep -i "Expires:"
else
    echo "[-] MISSING: Expires header"
fi

echo ""

# Check for Pragma header
if echo "$RESPONSE" | grep -iq "Pragma:"; then
    echo "[+] Pragma header found:"
    echo "$RESPONSE" | grep -i "Pragma:"
else
    echo "[-] MISSING: Pragma header (for HTTP/1.0 compatibility)"
fi

echo ""

# Check for ETag header
if echo "$RESPONSE" | grep -iq "ETag:"; then
    echo "[+] ETag header found:"
    echo "$RESPONSE" | grep -i "ETag:"
else
    echo "[-] MISSING: ETag header"
fi

echo ""

# Check for Last-Modified header
if echo "$RESPONSE" | grep -iq "Last-Modified:"; then
    echo "[+] Last-Modified header found:"
    echo "$RESPONSE" | grep -i "Last-Modified:"
else
    echo "[-] MISSING: Last-Modified header"
fi

echo ""

# Check for Vary header
if echo "$RESPONSE" | grep -iq "Vary:"; then
    echo "[+] Vary header found:"
    echo "$RESPONSE" | grep -i "Vary:"
else
    echo "[-] MISSING: Vary header"
fi

echo ""

# Check for HSTS header
if echo "$RESPONSE" | grep -iq "Strict-Transport-Security:"; then
    echo "[+] HSTS header found:"
    echo "$RESPONSE" | grep -i "Strict-Transport-Security:"
else
    echo "[-] MISSING: Strict-Transport-Security header (HSTS)"
fi

echo ""
echo "=== VULNERABILITY ASSESSMENT ==="
echo "The main page is missing Cache-Control headers that should prevent caching of sensitive content."
echo "This allows:"
echo "  1. Browsers to cache sensitive content with default behavior"
echo "  2. Proxy servers and CDNs to cache sensitive data"
echo "  3. Shared computers to expose cached sensitive information"
echo "  4. Corporate proxies to potentially expose cached data"
echo ""

# Compare with static files
echo "=== CHECKING STATIC FILES FOR COMPARISON ==="
echo "[*] Fetching headers from static CSS file..."
CSS_RESPONSE=$(curl -v "$TARGET_URL/static/css/style.css" 2>&1)

if echo "$CSS_RESPONSE" | grep -iq "Cache-Control:"; then
    echo "[+] Static file HAS Cache-Control header:"
    echo "$CSS_RESPONSE" | grep -i "Cache-Control:"
    echo ""
    echo "[!] INCONSISTENCY: Static files have cache headers but main page does not!"
else
    echo "[-] Static file also missing Cache-Control"
fi

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="