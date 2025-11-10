#!/bin/bash

# POC: Missing Security Headers on Session Cookie (Version 2)
# This script verifies that session cookies lack Secure and SameSite flags
# Follows the complete authentication flow to capture the session cookie

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"
USER_ID="10032"

echo "[*] Testing Session Cookie Security Flags"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Initial POST with username (get redirect to /password/{username})
echo "[*] Step 1: Initial authentication POST..."
RESPONSE1=$(curl -s -i -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD" \
  2>&1)

echo "[*] First response status:"
echo "$RESPONSE1" | head -5
echo ""

# Step 2: Complete the authentication flow by following redirect
# The form at /password/{username} contains the user_id hidden field
echo "[*] Step 2: Retrieving password form..."
FORM_PAGE=$(curl -s "$TARGET/password/$USERNAME" 2>&1)

# Step 3: POST to password endpoint with all credentials including user_id
echo "[*] Step 3: Submitting password form..."
RESPONSE2=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD&user_id=$USER_ID" \
  2>&1)

echo "[*] Second response (authentication completion):"
echo "$RESPONSE2" | head -15
echo ""

# Step 4: Extract and analyze Set-Cookie headers from all responses
echo "[*] Step 4: Analyzing Set-Cookie headers from both responses..."
COOKIES1=$(echo "$RESPONSE1" | grep -i "^Set-Cookie:")
COOKIES2=$(echo "$RESPONSE2" | grep -i "^Set-Cookie:")

if [ -z "$COOKIES1" ] && [ -z "$COOKIES2" ]; then
    echo "[*] No Set-Cookie headers in authentication responses"
    echo "[*] Attempting to check response from /dashboard..."
    RESPONSE3=$(curl -s -i "$TARGET/dashboard" 2>&1)
    COOKIES3=$(echo "$RESPONSE3" | grep -i "^Set-Cookie:")
    if [ -n "$COOKIES3" ]; then
        COOKIES="$COOKIES3"
        echo "[+] Found cookies in dashboard response"
    else
        COOKIES=""
    fi
else
    COOKIES="$COOKIES1$COOKIES2"
fi

echo "Set-Cookie headers found:"
echo "$COOKIES"
echo ""

# Step 5: Check for security flags
echo "[*] Step 5: Security Flag Analysis:"
echo ""

if [ -z "$COOKIES" ]; then
    echo "[!] No session cookies found in responses"
    echo "[*] Checking raw response for any cookie references..."
    echo "$RESPONSE2" | grep -i "cookie\|session"
    exit 1
fi

if echo "$COOKIES" | grep -qi "HttpOnly"; then
    echo "✓ HttpOnly flag: PRESENT"
else
    echo "✗ HttpOnly flag: MISSING"
fi

if echo "$COOKIES" | grep -qi "Secure"; then
    echo "✓ Secure flag: PRESENT"
else
    echo "✗ Secure flag: MISSING (VULNERABLE - cookie can be transmitted over HTTP)"
fi

if echo "$COOKIES" | grep -qi "SameSite"; then
    echo "✓ SameSite flag: PRESENT"
else
    echo "✗ SameSite flag: MISSING (VULNERABLE - susceptible to CSRF attacks)"
fi

echo ""
echo "[*] Summary:"
echo "Session cookie detected:"
echo "$COOKIES"
echo ""

# Check if both Secure and SameSite are missing
if ! echo "$COOKIES" | grep -qi "Secure" && ! echo "$COOKIES" | grep -qi "SameSite"; then
    echo "[!] VULNERABILITY CONFIRMED: Session cookie is missing both Secure and SameSite flags"
    echo "[!] Impact: Cookies vulnerable to interception and CSRF attacks"
    exit 0
else
    echo "[*] Some security flags are present"
    exit 1
fi