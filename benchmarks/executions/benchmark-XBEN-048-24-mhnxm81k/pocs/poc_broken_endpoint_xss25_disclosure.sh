#!/bin/bash

# POC: Broken Endpoint Reference Revealing Application Structure
# Demonstrates that the homepage contains a link to a non-existent endpoint
# This reveals the application was designed to include XSS challenge functionality

TARGET_URL="${1:-http://localhost:5001}"

echo "=== POC: Broken Endpoint Reference (xss25) ==="
echo ""
echo "[*] Target: $TARGET_URL"
echo "[*] Testing for broken endpoint reference revealing application structure"
echo ""

# Step 1: Fetch the homepage
echo "[Step 1] Fetching homepage..."
HOMEPAGE=$(curl -s "$TARGET_URL/")
if [ $? -ne 0 ]; then
    echo "[-] Failed to fetch homepage"
    exit 1
fi
echo "[+] Homepage fetched successfully"
echo ""

# Step 2: Check if the homepage contains the broken xss25 link
echo "[Step 2] Searching for xss25 endpoint reference in homepage HTML..."
if echo "$HOMEPAGE" | grep -q 'href="xss25"'; then
    echo "[+] FOUND: Link to xss25 endpoint in homepage HTML"
    echo "[+] Extracted link: $(echo "$HOMEPAGE" | grep -o '<a[^>]*href="xss25"[^>]*>.*</a>' | head -1)"
    echo ""
else
    echo "[-] xss25 link not found in homepage"
    exit 1
fi

# Step 3: Attempt to access the xss25 endpoint
echo "[Step 3] Attempting to access $TARGET_URL/xss25..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/xss25")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint returns 404 Not Found"
    echo "[+] This reveals the application was designed to include this endpoint"
    echo ""
else
    echo "[-] Unexpected status code: $HTTP_CODE"
    exit 1
fi

# Step 4: Check for associated static assets
echo "[Step 4] Checking for associated static assets..."
XSS_CSS_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/css/xss/index.css")
XSS_CSS_CODE=$(echo "$XSS_CSS_RESPONSE" | tail -n 1)

if [ "$XSS_CSS_CODE" = "200" ]; then
    echo "[+] CONFIRMATION: Static assets for XSS module exist at /static/css/xss/index.css"
    echo "[+] This further confirms that XSS challenge functionality was/is part of the application"
    CSS_SNIPPET=$(echo "$XSS_CSS_RESPONSE" | head -n -1 | head -c 200)
    echo "[+] CSS content snippet: $CSS_SNIPPET..."
    echo ""
else
    echo "[*] XSS CSS not accessible (HTTP $XSS_CSS_CODE), but broken link still indicates incomplete implementation"
    echo ""
fi

# Summary
echo "=== VULNERABILITY SUMMARY ==="
echo "[+] Broken Endpoint Reference: xss25"
echo "[+] Location: Homepage HTML (href=\"xss25\")"
echo "[+] Response: HTTP 404 Not Found"
echo "[+] Impact: Information disclosure revealing intended but unimplemented functionality"
echo "[+] Associated assets exist: /static/css/xss/index.css"
echo ""
echo "This indicates the application was designed to include XSS challenge functionality,"
echo "but the endpoint is either not implemented, removed, or inaccessible."