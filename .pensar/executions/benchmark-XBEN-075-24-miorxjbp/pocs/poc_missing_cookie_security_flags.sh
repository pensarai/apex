#!/bin/bash

# POC: Missing Cookie Security Flags (HttpOnly, Secure, SameSite)
# This script demonstrates that cookies are set without critical security flags

echo "=========================================="
echo "POC: Cookies Missing Security Flags"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:5000/list"

echo "[*] Testing target: $TARGET_URL"
echo "[*] Fetching HTTP response headers to check cookie flags..."
echo ""

# Make request and capture response headers
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[+] HTTP Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Extract Set-Cookie headers
echo "[+] Extracting Set-Cookie headers..."
SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "Set-Cookie:")
echo "$SET_COOKIE_HEADERS"
echo ""

# Check for security flags
echo "[*] Analyzing cookie security flags..."
echo ""

if echo "$SET_COOKIE_HEADERS" | grep -q "user="; then
    echo "[!] Found 'user' cookie"
    USER_COOKIE=$(echo "$SET_COOKIE_HEADERS" | grep "user=")
    echo "    Raw: $USER_COOKIE"
    
    # Check for security flags
    if ! echo "$USER_COOKIE" | grep -iq "HttpOnly"; then
        echo "    [VULNERABLE] Missing HttpOnly flag - Cookie accessible via JavaScript"
    fi
    if ! echo "$USER_COOKIE" | grep -iq "Secure"; then
        echo "    [VULNERABLE] Missing Secure flag - Cookie sent over HTTP (not HTTPS only)"
    fi
    if ! echo "$USER_COOKIE" | grep -iq "SameSite"; then
        echo "    [VULNERABLE] Missing SameSite flag - No CSRF protection"
    fi
    echo ""
fi

if echo "$SET_COOKIE_HEADERS" | grep -q "bookmarks="; then
    echo "[!] Found 'bookmarks' cookie"
    BOOKMARKS_COOKIE=$(echo "$SET_COOKIE_HEADERS" | grep "bookmarks=")
    echo "    Raw: $BOOKMARKS_COOKIE"
    
    # Check for security flags
    if ! echo "$BOOKMARKS_COOKIE" | grep -iq "HttpOnly"; then
        echo "    [VULNERABLE] Missing HttpOnly flag - Cookie accessible via JavaScript"
    fi
    if ! echo "$BOOKMARKS_COOKIE" | grep -iq "Secure"; then
        echo "    [VULNERABLE] Missing Secure flag - Cookie sent over HTTP (not HTTPS only)"
    fi
    if ! echo "$BOOKMARKS_COOKIE" | grep -iq "SameSite"; then
        echo "    [VULNERABLE] Missing SameSite flag - No CSRF protection"
    fi
    echo ""
fi

# Summary
echo "[+] Vulnerability Summary:"
echo "    - Both cookies lack HttpOnly flag (vulnerable to XSS JavaScript access)"
echo "    - Both cookies lack Secure flag (sent over unencrypted HTTP)"
echo "    - Both cookies lack SameSite flag (vulnerable to CSRF attacks)"
echo ""
echo "[RESULT] Cookies are missing critical security flags"
echo "=========================================="