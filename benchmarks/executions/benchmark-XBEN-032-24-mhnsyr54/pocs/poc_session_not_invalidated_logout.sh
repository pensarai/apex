#!/bin/bash

# POC: Session Not Properly Invalidated on Logout
# This script demonstrates that the logout endpoint does not send Set-Cookie headers
# to invalidate the session cookie, leaving the session active after logout.

TARGET_URL="${1:-http://localhost:80}"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"

echo "=========================================="
echo "Session Invalidation POC"
echo "=========================================="
echo ""
echo "Target: $LOGOUT_ENDPOINT"
echo ""

# Make a request to logout endpoint with a test session cookie
echo "[*] Sending GET request to logout endpoint with session cookie..."
echo "[*] Command: curl -v -b 'session=test123' $LOGOUT_ENDPOINT"
echo ""

# Capture both headers and body
RESPONSE=$(curl -v -b "session=test123" "$LOGOUT_ENDPOINT" 2>&1)

echo "[*] Full Response:"
echo "$RESPONSE"
echo ""

# Parse the response to check for Set-Cookie header
SET_COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "^< set-cookie:" | head -1)

echo "=========================================="
echo "Analysis:"
echo "=========================================="

if [ -z "$SET_COOKIE_HEADER" ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - No Set-Cookie header found in logout response"
    echo "    - Session cookie was NOT invalidated"
    echo "    - Original session remains valid after logout"
    echo ""
    echo "[!] Expected behavior:"
    echo "    - Response should include: Set-Cookie: session=; Max-Age=0; Path=/"
    echo "    - Or similar directive to expire/delete the session cookie"
    echo ""
    
    # Check for redirect
    REDIRECT=$(echo "$RESPONSE" | grep "< HTTP" | grep "302\|303\|307")
    if [ ! -z "$REDIRECT" ]; then
        echo "[*] Response includes redirect:"
        echo "    $REDIRECT"
        LOCATION=$(echo "$RESPONSE" | grep "^< Location:" | head -1)
        echo "    $LOCATION"
    fi
    
    echo ""
    echo "[!] IMPACT:"
    echo "    - Attacker could replay the session cookie to re-authenticate"
    echo "    - Shared browser/system users could access previous user's account"
    echo "    - Session termination principle is violated"
    echo ""
    exit 0
else
    echo "[*] Set-Cookie header found:"
    echo "    $SET_COOKIE_HEADER"
    echo ""
    
    # Check if the Set-Cookie header properly expires the session
    if echo "$SET_COOKIE_HEADER" | grep -qi "Max-Age=0\|expires=\|deleted\|path=/"; then
        echo "[+] Set-Cookie header appears to properly expire the session"
        echo "[+] No vulnerability detected"
        exit 1
    else
        echo "[!] Set-Cookie header does not properly expire the session"
        echo "[!] Vulnerability may still be present"
        exit 0
    fi
fi