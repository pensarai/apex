#!/bin/bash

# POC: Information Disclosure - Broken Challenge Link and Incomplete Feature
# Demonstrates: 
# 1. Broken link to non-existent XSS25 challenge endpoint
# 2. Server header disclosing technology stack (Werkzeug/Python version)

TARGET="http://localhost:5001"
CHALLENGE_ENDPOINT="/xss25"

echo "=== Information Disclosure - Broken Challenge Link POC ==="
echo

# Step 1: Get main page and check for broken link
echo "[*] Step 1: Fetching main page from $TARGET/"
echo "    Checking for links to challenge endpoints..."
echo

MAIN_PAGE=$(curl -s "$TARGET/")
if echo "$MAIN_PAGE" | grep -q "xss25"; then
    echo "[✓] Found reference to 'xss25' in main page"
    echo "    Link href found:"
    echo "$MAIN_PAGE" | grep -oP "href='[^']*xss25[^']*'" | head -1
else
    echo "[-] No reference to xss25 found in main page"
fi
echo

# Step 2: Try to access the non-existent endpoint
echo "[*] Step 2: Attempting to access challenge endpoint: $TARGET$CHALLENGE_ENDPOINT"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$CHALLENGE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "404" ]; then
    echo "[✓] VULNERABLE: Endpoint returns 404 (Not Found)"
    echo "    This indicates the advertised feature is incomplete/broken"
else
    echo "[-] Endpoint returned status $HTTP_CODE (not 404)"
fi
echo

# Step 3: Extract Server header disclosing technology stack
echo "[*] Step 3: Checking Server header for technology stack disclosure"
SERVER_HEADER=$(curl -s -i "$TARGET/" 2>/dev/null | grep -i "^Server:" | cut -d' ' -f2-)
echo "    Server Header: $SERVER_HEADER"
if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[✓] VULNERABLE: Server header discloses Werkzeug/Python version"
    echo "    Detected: $SERVER_HEADER"
    echo "    This aids attackers in identifying framework-specific vulnerabilities"
else
    echo "[-] Werkzeug not detected in Server header"
fi
echo

# Step 4: Summary
echo "[*] VULNERABILITY SUMMARY:"
echo "    1. Broken challenge link pointing to non-existent endpoint"
echo "    2. Technology stack disclosure in Server header"
echo "    3. Application appears to be in incomplete/development state"
echo

exit 0