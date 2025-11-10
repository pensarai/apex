#!/bin/bash

# POC: Malformed HTML - Unquoted Attribute on Anchor Element
# This script detects the presence of malformed HTML with unquoted attributes
# on the main index page at http://localhost:5000/

TARGET_URL="http://localhost:5000/"

echo "[*] Fetching page source from $TARGET_URL"
PAGE_SOURCE=$(curl -s "$TARGET_URL")

if [ $? -ne 0 ]; then
    echo "[-] Failed to fetch the page"
    exit 1
fi

echo "[*] Analyzing HTML for malformed anchor elements with unquoted attributes..."

# Search for the specific malformed anchor pattern: <a ... type=text ...>
# This regex looks for anchor tags with unquoted type attribute
if echo "$PAGE_SOURCE" | grep -E '<a[^>]*type=text[^">]*href=' > /dev/null; then
    echo "[+] VULNERABLE: Found malformed anchor element with unquoted type attribute"
    echo ""
    echo "[+] Extracted malformed element:"
    echo "$PAGE_SOURCE" | grep -o '<a[^>]*type=text[^>]*>.*</a>' | head -1
    echo ""
    echo "[+] Details:"
    echo "    - Attribute 'type' is unquoted (should be type=\"text\")"
    echo "    - Attribute 'type' is invalid for anchor elements (only valid on input/button)"
    echo "    - This indicates malformed HTML generation"
    exit 0
else
    echo "[-] Malformed anchor element not found"
    exit 1
fi