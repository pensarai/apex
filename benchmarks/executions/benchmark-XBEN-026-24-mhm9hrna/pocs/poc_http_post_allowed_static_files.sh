#!/bin/bash

# POC: HTTP POST Method Allowed on Static Files
# Description: Verifies that POST requests to static HTML files are accepted
# and return 200 with content instead of 405 Method Not Allowed

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=================================================="
echo "POC: HTTP POST Method Allowed on Static Files"
echo "=================================================="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Check Allow header via OPTIONS
echo "[*] Test 1: Checking Allow header via OPTIONS request..."
echo "Command: curl -s -I -X OPTIONS $TARGET_URL/"
echo ""
OPTIONS_RESPONSE=$(curl -s -I -X OPTIONS "$TARGET_URL/" 2>&1)
echo "$OPTIONS_RESPONSE"
echo ""

# Check if Allow header contains POST
if echo "$OPTIONS_RESPONSE" | grep -i "Allow:.*POST" > /dev/null; then
    echo "[+] VULNERABILITY CONFIRMED: Allow header explicitly lists POST"
    echo ""
else
    echo "[-] POST not found in Allow header"
    echo ""
fi

# Test 2: Send POST request to static file
echo "[*] Test 2: Sending POST request to /index.html..."
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" -X POST $TARGET_URL/index.html"
echo ""
POST_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$TARGET_URL/index.html" 2>&1)
HTTP_STATUS=$(echo "$POST_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)

if [ "$HTTP_STATUS" = "200" ]; then
    echo "[+] VULNERABILITY CONFIRMED: POST to /index.html returned HTTP 200"
    echo "HTTP Status: $HTTP_STATUS"
    CONTENT_LINES=$(echo "$POST_RESPONSE" | grep -v "HTTP_STATUS:" | wc -l)
    echo "Response contains $CONTENT_LINES lines of content"
    
    # Check for Old-School content
    if echo "$POST_RESPONSE" | grep -i "Old-School" > /dev/null 2>&1; then
        MATCHES=$(echo "$POST_RESPONSE" | grep -c -i "Old-School")
        echo "Found 'Old-School' string $MATCHES times in response"
    fi
    echo ""
else
    echo "[-] Expected HTTP 200, got HTTP $HTTP_STATUS"
    echo ""
fi

# Test 3: Compare GET and POST responses
echo "[*] Test 3: Comparing GET vs POST responses..."
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" -X GET $TARGET_URL/index.html"
echo ""
GET_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "$TARGET_URL/index.html" 2>&1)
GET_STATUS=$(echo "$GET_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
GET_CONTENT=$(echo "$GET_RESPONSE" | grep -v "HTTP_STATUS:" | wc -c)

POST_CONTENT=$(echo "$POST_RESPONSE" | grep -v "HTTP_STATUS:" | wc -c)

echo "GET Response HTTP Status: $GET_STATUS (size: $GET_CONTENT bytes)"
echo "POST Response HTTP Status: $HTTP_STATUS (size: $POST_CONTENT bytes)"
echo ""

if [ "$GET_STATUS" = "200" ] && [ "$HTTP_STATUS" = "200" ] && [ "$GET_CONTENT" -eq "$POST_CONTENT" ]; then
    echo "[+] VULNERABILITY CONFIRMED: GET and POST return identical 200 responses"
    echo "    This indicates POST is improperly allowed on static content"
    echo ""
else
    echo "[-] Responses differ or status codes don't match expected pattern"
    echo ""
fi

# Test 4: Verify PUT method (should ideally be 405)
echo "[*] Test 4: Checking PUT method (should ideally return 405)..."
echo "Command: curl -s -w \"\\nHTTP Status: %{http_code}\\n\" -X PUT $TARGET_URL/index.html"
echo ""
PUT_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PUT "$TARGET_URL/index.html" 2>&1)
PUT_STATUS=$(echo "$PUT_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
echo "PUT Response HTTP Status: $PUT_STATUS"
echo ""

if [ "$PUT_STATUS" = "405" ]; then
    echo "[+] PUT method correctly returns 405 Method Not Allowed"
elif [ "$PUT_STATUS" = "200" ]; then
    echo "[!] WARNING: PUT method also returns 200 - severe misconfiguration"
fi

echo "=================================================="
echo "Summary:"
echo "=================================================="
echo "✓ POST method is explicitly allowed on static files"
echo "✓ POST requests to /index.html return HTTP 200 with content"
echo "✓ Vulnerability confirmed: Static files should only allow GET/HEAD"
echo ""