#!/bin/bash

# POC: Missing Secure Flag on Session and CSRF Cookies (Version 2)
# This script demonstrates that session and CSRF cookies lack the Secure flag
# Uses curl with -D option to dump headers to file for better parsing

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_PAGE="${TARGET_URL}/accounts/login/"
REGISTER_PAGE="${TARGET_URL}/accounts/register/step1/"
LOGOUT_PAGE="${TARGET_URL}/accounts/logout/"

# Temporary files for headers
TEMP_HEADERS=$(mktemp)
trap "rm -f $TEMP_HEADERS" EXIT

echo "=========================================="
echo "POC: Missing Secure Flag on Cookies"
echo "=========================================="
echo ""
echo "Target URL: $TARGET_URL"
echo ""

VULNERABLE=0

# Test 1: Check cookies from login page
echo "[*] Test 1: Checking Set-Cookie headers from login page"
echo "Endpoint: $LOGIN_PAGE"
echo ""

curl -s -D "$TEMP_HEADERS" "$LOGIN_PAGE" > /dev/null 2>&1

# Extract all Set-Cookie headers
CSRF_HEADER=$(grep -i "^set-cookie:.*csrftoken" "$TEMP_HEADERS")
SESSION_HEADER=$(grep -i "^set-cookie:.*sessionid" "$TEMP_HEADERS")

if [ -n "$CSRF_HEADER" ]; then
    echo "csrftoken Cookie found:"
    echo "$CSRF_HEADER"
    echo ""
    
    # Check for Secure flag
    if echo "$CSRF_HEADER" | grep -qi ";\s*secure"; then
        echo "  ✓ Secure flag present"
    else
        echo "  ✗ Secure flag MISSING (VULNERABLE)"
        VULNERABLE=1
    fi
    
    # Check for HttpOnly flag
    if echo "$CSRF_HEADER" | grep -qi ";\s*httponly"; then
        echo "  ✓ HttpOnly flag present"
    else
        echo "  ✗ HttpOnly flag MISSING"
    fi
    
    # Check for SameSite
    if echo "$CSRF_HEADER" | grep -qi "samesite"; then
        SAMESITE=$(echo "$CSRF_HEADER" | grep -io "samesite[^;]*")
        echo "  ✓ $SAMESITE present"
    else
        echo "  ✗ SameSite flag MISSING"
    fi
else
    echo "  [-] No csrftoken cookie found in login response"
fi

if [ -n "$SESSION_HEADER" ]; then
    echo ""
    echo "sessionid Cookie found:"
    echo "$SESSION_HEADER"
    echo ""
    
    # Check for Secure flag
    if echo "$SESSION_HEADER" | grep -qi ";\s*secure"; then
        echo "  ✓ Secure flag present"
    else
        echo "  ✗ Secure flag MISSING (VULNERABLE)"
        VULNERABLE=1
    fi
    
    # Check for HttpOnly flag
    if echo "$SESSION_HEADER" | grep -qi ";\s*httponly"; then
        echo "  ✓ HttpOnly flag present"
    else
        echo "  ✗ HttpOnly flag MISSING"
    fi
    
    # Check for SameSite
    if echo "$SESSION_HEADER" | grep -qi "samesite"; then
        SAMESITE=$(echo "$SESSION_HEADER" | grep -io "samesite[^;]*")
        echo "  ✓ $SAMESITE present"
    else
        echo "  ✗ SameSite flag MISSING"
    fi
else
    echo "  [-] No sessionid cookie found in login response"
fi

echo ""
echo "=========================================="
echo "[*] Test 2: Checking cookies from logout page"
echo "Endpoint: $LOGOUT_PAGE"
echo ""

curl -s -D "$TEMP_HEADERS" "$LOGOUT_PAGE" > /dev/null 2>&1

# Extract Set-Cookie headers
SESSION_HEADER=$(grep -i "^set-cookie:.*sessionid" "$TEMP_HEADERS")

if [ -n "$SESSION_HEADER" ]; then
    echo "sessionid Cookie (logout) found:"
    echo "$SESSION_HEADER"
    echo ""
    
    # Check for Secure flag
    if echo "$SESSION_HEADER" | grep -qi ";\s*secure"; then
        echo "  ✓ Secure flag present"
    else
        echo "  ✗ Secure flag MISSING (VULNERABLE)"
        VULNERABLE=1
    fi
    
    # Check for HttpOnly flag
    if echo "$SESSION_HEADER" | grep -qi ";\s*httponly"; then
        echo "  ✓ HttpOnly flag present"
    else
        echo "  ✗ HttpOnly flag MISSING"
    fi
else
    echo "  [-] No sessionid cookie found in logout response"
fi

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="
echo ""

if [ $VULNERABLE -eq 1 ]; then
    echo "[VULNERABLE] One or more cookies are missing the Secure flag!"
    echo ""
    echo "Impact:"
    echo "- In HTTPS environments, cookies without the Secure flag can be"
    echo "  intercepted over unencrypted connections (MITM attacks)"
    echo "- Session hijacking and CSRF attacks become possible"
    echo "- Affected cookies: Those without Secure flag above"
    echo ""
    echo "Remediation:"
    echo "- Set SESSION_COOKIE_SECURE=True in Django settings"
    echo "- Set CSRF_COOKIE_SECURE=True in Django settings"
    echo "- Ensure the application is deployed over HTTPS in production"
    echo "- Configure HSTS header to enforce HTTPS"
    echo ""
    exit 1
else
    echo "[PASS] All cookies have the Secure flag set"
    exit 0
fi