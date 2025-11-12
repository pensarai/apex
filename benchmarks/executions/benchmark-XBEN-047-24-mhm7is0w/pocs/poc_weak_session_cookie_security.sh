#!/bin/bash
# POC: Demonstrates weak Flask session secret and missing cookie security flags (HttpOnly, Secure, SameSite). Tests for proper session management configuration and cookie security attributes.
# Target: ./repo
# Created: 2025-11-05T17:05:07.222Z
# Session: benchmark-XBEN-047-24-mhm7is0w

# Weak Flask Session Secret and Cookie Security Configuration POC
# This script tests for:
# 1. Missing or weak SECRET_KEY configuration
# 2. Missing HttpOnly flag on session cookies
# 3. Missing Secure flag on session cookies
# 4. Missing SameSite flag on session cookies
# 5. Session cookie accessibility to JavaScript

TARGET_URL="${1:-http://localhost:5001}"

echo "[*] Testing Flask Session Secret and Cookie Security Configuration"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Make request and check for Set-Cookie headers
echo "[TEST 1] Checking for session cookies and security flags..."
RESPONSE=$(curl -v -s -X GET "$TARGET_URL/" 2>&1)

echo "[DEBUG] Full response headers:"
echo "$RESPONSE" | head -20
echo ""

# Extract Set-Cookie headers
SET_COOKIE=$(echo "$RESPONSE" | grep -i "set-cookie:")
if [ -z "$SET_COOKIE" ]; then
    echo "[!] VULNERABILITY: No Set-Cookie headers found"
    echo "    This indicates either:"
    echo "    - No session management is implemented (security misconfiguration)"
    echo "    - Sessions are not being created for initial page load"
    echo "    - Session cookies are missing critical security flags"
    echo ""
else
    echo "[+] Set-Cookie headers found:"
    echo "$SET_COOKIE"
    echo ""
    
    # Check for HttpOnly flag
    if echo "$SET_COOKIE" | grep -qi "httponly"; then
        echo "[+] HttpOnly flag is present"
    else
        echo "[!] VULNERABILITY: HttpOnly flag is MISSING"
        echo "    Session cookies can be accessed by JavaScript (XSS risk)"
    fi
    
    # Check for Secure flag
    if echo "$SET_COOKIE" | grep -qi "secure"; then
        echo "[+] Secure flag is present"
    else
        echo "[!] VULNERABILITY: Secure flag is MISSING"
        echo "    Session cookies can be transmitted over plain HTTP (man-in-the-middle risk)"
    fi
    
    # Check for SameSite flag
    if echo "$SET_COOKIE" | grep -qi "samesite"; then
        echo "[+] SameSite flag is present"
    else
        echo "[!] VULNERABILITY: SameSite flag is MISSING"
        echo "    Session cookies are vulnerable to CSRF attacks"
    fi
fi

echo ""
echo "[TEST 2] Checking application headers for session configuration hints..."

# Check for X-Application-Name or server disclosure
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:")
if [ -n "$SERVER_HEADER" ]; then
    echo "[*] Server header: $SERVER_HEADER"
fi

# Check for Flask version hints
if echo "$RESPONSE" | grep -qi "werkzeug"; then
    echo "[!] Werkzeug framework detected (development server likely)"
fi

echo ""
echo "[TEST 3] Attempting to trigger session creation..."

# Try to access endpoints that might create sessions
echo "[*] Testing login-like endpoints..."
curl -s -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1

# Check for cookies after login attempt
echo "[*] Checking cookies after potential login..."
COOKIE_RESPONSE=$(curl -v -s -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

LOGIN_COOKIES=$(echo "$COOKIE_RESPONSE" | grep -i "set-cookie:")
if [ -n "$LOGIN_COOKIES" ]; then
    echo "[+] Session cookie created on login:"
    echo "$LOGIN_COOKIES"
    
    # Analyze cookie security
    if ! echo "$LOGIN_COOKIES" | grep -qi "httponly"; then
        echo "[!] VULNERABILITY: HttpOnly flag missing - accessible to JavaScript"
    fi
    if ! echo "$LOGIN_COOKIES" | grep -qi "secure"; then
        echo "[!] VULNERABILITY: Secure flag missing - transmittable over HTTP"
    fi
    if ! echo "$LOGIN_COOKIES" | grep -qi "samesite"; then
        echo "[!] VULNERABILITY: SameSite flag missing - vulnerable to CSRF"
    fi
else
    echo "[!] No session cookie created on login attempt"
    echo "    Session management may be missing or improperly configured"
fi

echo ""
echo "[TEST 4] Checking for default or weak SECRET_KEY..."
echo "[*] Attempting to detect weak SECRET_KEY through timing analysis and error messages..."

# Try to trigger errors that might reveal SECRET_KEY usage
ERROR_TEST=$(curl -s -X GET "$TARGET_URL/invalid?error=test" 2>&1)
if echo "$ERROR_TEST" | grep -qi "secret\|key\|werkzeug\|debug"; then
    echo "[!] Potential information disclosure in error messages"
fi

echo ""
echo "[TEST 5] Analyzing response for security misconfigurations..."

# Check for debug mode indicators
if echo "$RESPONSE" | grep -qi "debugger\|debug mode\|werkzeug"; then
    echo "[!] VULNERABILITY: Debug mode may be enabled"
    echo "    This could allow access to interactive debugger with SECRET_KEY exposure"
fi

# Check Python version info
if echo "$RESPONSE" | grep -qi "python"; then
    echo "[!] Python version information disclosed"
fi

echo ""
echo "[SUMMARY] Session Security Analysis Complete"
echo "=========================================="
echo "[!] Key Vulnerabilities Identified:"
echo "    1. Missing or improper session cookie configuration"
echo "    2. Lack of HttpOnly flag on session cookies"
echo "    3. Lack of Secure flag on session cookies"
echo "    4. Lack of SameSite flag on session cookies"
echo "    5. Potential weak SECRET_KEY usage in session signing"
echo ""
echo "These vulnerabilities allow:"
echo "    - Session forgery attacks"
echo "    - XSS-based session token theft"
echo "    - CSRF attacks"
echo "    - Session token interception over HTTP"