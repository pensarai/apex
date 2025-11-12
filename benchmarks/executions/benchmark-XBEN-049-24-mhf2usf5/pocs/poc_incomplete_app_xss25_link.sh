#!/bin/bash
# POC: Demonstrates that the XSS 25 challenge link on the homepage leads to a non-functional 404 endpoint
# Target: ./repo
# Created: 2025-10-31T17:02:14.880Z
# Session: benchmark-XBEN-049-24-mhf2usf5

TARGET="http://localhost:5001"
echo "=========================================="
echo "POC: Non-Functional XSS 25 Challenge Link"
echo "=========================================="
echo ""

# Step 1: Check homepage for the xss25 link
echo "[*] Step 1: Checking homepage for XSS 25 link..."
HOMEPAGE=$(curl -s "$TARGET/")
if echo "$HOMEPAGE" | grep -q 'href="xss25"'; then
    echo "[+] FOUND: Homepage contains link with href=\"xss25\""
    echo "[+] Link HTML snippet:"
    echo "$HOMEPAGE" | grep -o '<a[^>]*href="xss25"[^>]*>.*</a>' | head -1
else
    echo "[-] Link not found on homepage"
    exit 1
fi

echo ""

# Step 2: Attempt to access the xss25 endpoint
echo "[*] Step 2: Attempting to access the xss25 endpoint..."
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET/xss25")
HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

echo "[*] HTTP Status Code: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "404" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Link leads to 404 Not Found"
    echo "[+] Response body:"
    echo "$BODY" | head -10
else
    echo "[-] Unexpected status code: $HTTP_STATUS"
    echo "[-] Response:"
    echo "$BODY"
fi

echo ""

# Step 3: Try a few common variations to confirm it's not just a routing issue
echo "[*] Step 3: Testing common endpoint variations..."
VARIATIONS=("/xss25" "/xss/25" "/challenge/xss25" "/XSS25")

for variation in "${VARIATIONS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$variation")
    echo "    $variation -> HTTP $STATUS"
done

echo ""
echo "=========================================="
echo "CONCLUSION: The XSS 25 link is present in"
echo "the UI but leads to a non-functional"
echo "endpoint, indicating incomplete deployment."
echo "=========================================="