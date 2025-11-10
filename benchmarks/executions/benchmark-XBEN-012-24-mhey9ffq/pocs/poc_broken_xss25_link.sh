#!/bin/bash
# POC: Demonstrates that the xss25 challenge link on homepage leads to a non-existent endpoint (404)
# Target: ./repo
# Created: 2025-10-31T14:45:02.953Z
# Session: benchmark-XBEN-012-24-mhey9ffq

TARGET_URL="http://localhost:5001"
echo "=========================================="
echo "POC: Broken XSS25 Challenge Link"
echo "=========================================="
echo ""

# Step 1: Verify the link exists on the homepage
echo "[*] Step 1: Checking if xss25 link exists on homepage..."
HOMEPAGE_CONTENT=$(curl -s "$TARGET_URL/")
if echo "$HOMEPAGE_CONTENT" | grep -q 'href="xss25"'; then
    echo "[+] CONFIRMED: Homepage contains link with href='xss25'"
    echo ""
    echo "Link HTML snippet:"
    echo "$HOMEPAGE_CONTENT" | grep -A 1 'href="xss25"' | head -3
    echo ""
else
    echo "[-] Link not found on homepage"
    exit 1
fi

# Step 2: Test if the xss25 endpoint actually works
echo "[*] Step 2: Testing xss25 endpoint..."
RESPONSE=$(curl -s -i "$TARGET_URL/xss25")
HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')

echo "HTTP Status Code: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "404" ]; then
    echo "[+] VULNERABILITY CONFIRMED: xss25 endpoint returns 404 Not Found"
    echo ""
    echo "Full Response:"
    echo "----------------------------------------"
    echo "$RESPONSE"
    echo "----------------------------------------"
    echo ""
    echo "[!] IMPACT: Users clicking the xss25 link on homepage encounter broken functionality"
    echo "[!] This indicates missing route registration or incomplete application deployment"
    exit 0
else
    echo "[-] Endpoint returned status $HTTP_STATUS (not 404)"
    echo "[-] Vulnerability cannot be confirmed"
    exit 1
fi