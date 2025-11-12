#!/bin/bash

# POC: Missing Secure Flag on Session and CSRF Cookies
# This script demonstrates that session and CSRF cookies lack the Secure flag

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_PAGE="${TARGET_URL}/accounts/login/"
REGISTER_PAGE="${TARGET_URL}/accounts/register/step1/"

echo "=========================================="
echo "POC: Missing Secure Flag on Cookies"
echo "=========================================="
echo ""
echo "Target URL: $TARGET_URL"
echo ""

# Test 1: Check csrftoken cookie from login page
echo "[*] Test 1: Checking csrftoken from login page ($LOGIN_PAGE)"
echo "Sending GET request to capture Set-Cookie headers..."
echo ""

LOGIN_RESPONSE=$(curl -v "$LOGIN_PAGE" 2>&1)
CSRF_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie.*csrftoken")

if [ -n "$CSRF_COOKIE" ]; then
    echo "Found csrftoken cookie header:"
    echo "$CSRF_COOKIE"
    echo ""
    
    # Check for Secure flag
    if echo "$CSRF_COOKIE" | grep -qi "secure"; then
        echo "[PASS] Secure flag found on csrftoken"
    else
        echo "[VULNERABLE] Secure flag MISSING on csrftoken cookie"
    fi
    
    # Check for HttpOnly flag
    if echo "$CSRF_COOKIE" | grep -qi "httponly"; then
        echo "[INFO] HttpOnly flag found on csrftoken"
    else
        echo "[WEAKNESS] HttpOnly flag MISSING on csrftoken cookie"
    fi
    
    # Check for SameSite
    if echo "$CSRF_COOKIE" | grep -qi "samesite"; then
        echo "[INFO] SameSite flag found on csrftoken"
    else
        echo "[WEAKNESS] SameSite flag MISSING on csrftoken cookie"
    fi
else
    echo "[-] Could not find csrftoken cookie in response"
fi

echo ""
echo "=========================================="
echo "[*] Test 2: Checking sessionid from register page ($REGISTER_PAGE)"
echo "Sending POST request with CSRF token to capture sessionid..."
echo ""

# First get CSRF token
CSRF_TOKEN=$(curl -s "$LOGIN_PAGE" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')

if [ -n "$CSRF_TOKEN" ]; then
    echo "CSRF Token obtained: ${CSRF_TOKEN:0:20}..."
    echo ""
    
    # Try to create a session by posting to register
    REGISTER_RESPONSE=$(curl -v -X POST "$REGISTER_PAGE" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "csrfmiddlewaretoken=$CSRF_TOKEN&name=TestUser&email=test@example.com&phone=1234567890" \
        2>&1)
    
    SESSION_COOKIE=$(echo "$REGISTER_RESPONSE" | grep -i "set-cookie.*sessionid")
    
    if [ -n "$SESSION_COOKIE" ]; then
        echo "Found sessionid cookie header:"
        echo "$SESSION_COOKIE"
        echo ""
        
        # Check for Secure flag
        if echo "$SESSION_COOKIE" | grep -qi "secure"; then
            echo "[PASS] Secure flag found on sessionid"
        else
            echo "[VULNERABLE] Secure flag MISSING on sessionid cookie"
        fi
        
        # Check for HttpOnly flag
        if echo "$SESSION_COOKIE" | grep -qi "httponly"; then
            echo "[INFO] HttpOnly flag found on sessionid"
        else
            echo "[WEAKNESS] HttpOnly flag MISSING on sessionid cookie"
        fi
        
        # Check for SameSite
        if echo "$SESSION_COOKIE" | grep -qi "samesite"; then
            echo "[INFO] SameSite flag found on sessionid"
        else
            echo "[WEAKNESS] SameSite flag MISSING on sessionid cookie"
        fi
    else
        echo "[-] Could not find sessionid cookie in response"
        echo "    This may be expected if POST validation failed"
    fi
else
    echo "[-] Could not obtain CSRF token from login page"
fi

echo ""
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""
echo "If the output shows '[VULNERABLE] Secure flag MISSING' for either"
echo "csrftoken or sessionid cookies, this confirms that cookies are"
echo "being transmitted without the Secure flag protection."
echo ""
echo "In production with HTTPS, this would allow MITM attackers to"
echo "intercept these cookies through network packet capture."
echo ""