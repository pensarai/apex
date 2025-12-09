#!/bin/bash

# POC: Insecure Session Cookie Configuration
# Tests for missing security flags: HttpOnly, Secure, SameSite
# Target: http://localhost:8080/api/login.php

echo "=========================================="
echo "SESSION COOKIE SECURITY ANALYSIS POC"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:8080/api/login.php"
USERNAME="testuser1"
PASSWORD="password123"

echo "[*] Test 1: Analyzing Set-Cookie Header"
echo "[*] Making login request to: $TARGET_URL"
echo ""

# Capture response headers
RESPONSE=$(curl -i -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD")

# Extract Set-Cookie header
COOKIE_HEADER=$(echo "$RESPONSE" | grep -i "^set-cookie:" | head -1)

if [ -z "$COOKIE_HEADER" ]; then
    echo "[-] ERROR: No Set-Cookie header found in response"
    echo ""
    echo "Full response headers:"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Set-Cookie Header Found:"
echo "    $COOKIE_HEADER"
echo ""

# Check for security flags
echo "[*] Test 2: Checking for Security Flags"
echo ""

# Check HttpOnly flag
if echo "$COOKIE_HEADER" | grep -qi "HttpOnly"; then
    echo "[+] HttpOnly flag: PRESENT (Secure)"
    HTTPONLY_SECURE=1
else
    echo "[-] HttpOnly flag: MISSING (Vulnerable - XSS can steal cookie)"
    HTTPONLY_SECURE=0
fi

# Check Secure flag
if echo "$COOKIE_HEADER" | grep -qi "Secure"; then
    echo "[+] Secure flag: PRESENT (Secure)"
    SECURE_FLAG=1
else
    echo "[-] Secure flag: MISSING (Vulnerable - Cookie can be transmitted over HTTP)"
    SECURE_FLAG=0
fi

# Check SameSite attribute
if echo "$COOKIE_HEADER" | grep -qi "SameSite"; then
    SAMESITE_VALUE=$(echo "$COOKIE_HEADER" | grep -oiE "SameSite=[^;]+" | cut -d= -f2)
    echo "[+] SameSite attribute: PRESENT (Value: $SAMESITE_VALUE)"
    SAMESITE_SECURE=1
else
    echo "[-] SameSite attribute: MISSING (Vulnerable - CSRF attacks possible)"
    SAMESITE_SECURE=0
fi

echo ""
echo "[*] Test 3: Vulnerability Assessment"
echo ""

VULNERABILITY_COUNT=0

if [ $HTTPONLY_SECURE -eq 0 ]; then
    echo "[-] VULNERABILITY 1: Missing HttpOnly Flag"
    echo "    Impact: XSS attacks can read session cookie via JavaScript"
    echo "    Attack: document.cookie can access PHPSESSID"
    ((VULNERABILITY_COUNT++))
fi

if [ $SECURE_FLAG -eq 0 ]; then
    echo "[-] VULNERABILITY 2: Missing Secure Flag"
    echo "    Impact: Cookie can be transmitted over unencrypted HTTP"
    echo "    Attack: MITM attacker can intercept session cookie"
    ((VULNERABILITY_COUNT++))
fi

if [ $SAMESITE_SECURE -eq 0 ]; then
    echo "[-] VULNERABILITY 3: Missing SameSite Attribute"
    echo "    Impact: Cookie sent in cross-site requests (CSRF)"
    echo "    Attack: Cross-site requests automatically include session cookie"
    ((VULNERABILITY_COUNT++))
fi

echo ""
echo "[*] Test 4: Cookie Content Analysis"
echo ""

# Extract just the cookie name and value
COOKIE_LINE=$(echo "$COOKIE_HEADER" | grep -oE "PHPSESSID=[^;]+")
echo "[+] Cookie Value: $COOKIE_LINE"
echo ""

# Parse the path
PATH_VALUE=$(echo "$COOKIE_HEADER" | grep -oE "path=[^;]+" | cut -d= -f2)
echo "[+] Path Setting: $PATH_VALUE"
echo ""

echo "[*] Test 5: Security Configuration Verdict"
echo ""

if [ $VULNERABILITY_COUNT -eq 3 ]; then
    echo "[!] CRITICAL INSECURITY: All three security flags are missing!"
    echo "    The session cookie is highly vulnerable to:"
    echo "    - XSS-based session hijacking"
    echo "    - MITM attacks (HTTP interception)"
    echo "    - CSRF attacks"
    echo ""
    exit 0
elif [ $VULNERABILITY_COUNT -gt 0 ]; then
    echo "[!] HIGH RISK: $VULNERABILITY_COUNT security flag(s) missing"
    echo ""
    exit 0
else
    echo "[+] All security flags are properly configured"
    echo ""
    exit 1
fi