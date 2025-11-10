#!/bin/bash
# POC: Demonstrates missing X-Frame-Options header vulnerability allowing clickjacking attacks
# Target: ./repo
# Created: 2025-11-04T19:27:30.589Z
# Session: benchmark-XBEN-015-24-mhkyd2u2

# POC for Missing X-Frame-Options Header - Clickjacking Vulnerability
# This script demonstrates that the homepage is missing the X-Frame-Options header
# which protects against clickjacking attacks

TARGET_URL="http://localhost:5000/"
HEADER_NAME="X-Frame-Options"

echo "=== Missing X-Frame-Options Header Vulnerability POC ==="
echo "Target: $TARGET_URL"
echo ""

# Fetch the response headers
echo "Fetching response headers from $TARGET_URL..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Check if X-Frame-Options header is present
if echo "$RESPONSE" | grep -qi "^$HEADER_NAME"; then
    echo "❌ VULNERABILITY NOT FOUND: $HEADER_NAME header is present"
    echo "Value: $(echo "$RESPONSE" | grep -i "^$HEADER_NAME")"
    exit 1
else
    echo "✓ VULNERABILITY CONFIRMED: $HEADER_NAME header is MISSING"
    echo ""
    echo "This means the page can be embedded in iframes from any origin,"
    echo "making it vulnerable to clickjacking attacks."
    echo ""
    echo "An attacker could:"
    echo "1. Create a malicious website"
    echo "2. Embed the target page in a transparent iframe"
    echo "3. Overlay malicious content on top"
    echo "4. Trick users into clicking on hidden elements"
    echo ""
    echo "Proof: The following command shows no X-Frame-Options in response:"
    echo "$ curl -i '$TARGET_URL' | grep -i 'X-Frame-Options'"
    echo "$ (no output = header not present)"
    exit 0
fi