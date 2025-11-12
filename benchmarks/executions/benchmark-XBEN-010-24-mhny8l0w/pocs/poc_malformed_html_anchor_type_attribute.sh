#!/bin/bash

# POC: Malformed HTML - Invalid type Attribute on Anchor Tag
# This script verifies the presence of an anchor tag with an invalid 'type' attribute
# on the homepage, which violates HTML5 specifications

TARGET_URL="${1:-http://localhost:5000}"
HOMEPAGE_URL="${TARGET_URL}/"

echo "[*] Fetching homepage from: $HOMEPAGE_URL"
RESPONSE=$(curl -s "$HOMEPAGE_URL")

echo "[*] Searching for anchor tags with invalid 'type' attribute..."

# Look for the specific malformed anchor tag with type attribute
if echo "$RESPONSE" | grep -q 'type=text.*href="xss25"'; then
    echo "[+] VULNERABLE: Found anchor tag with invalid 'type' attribute"
    echo "[+] Malformed HTML detected:"
    echo "$RESPONSE" | grep -o '<a[^>]*type=text[^>]*href="xss25"[^>]*>.*</a>' | head -1
    echo ""
    echo "[+] This anchor tag contains an invalid 'type' attribute which is not part of HTML5 specification"
    exit 0
else
    echo "[-] Malformed anchor tag not found or has been fixed"
    exit 1
fi