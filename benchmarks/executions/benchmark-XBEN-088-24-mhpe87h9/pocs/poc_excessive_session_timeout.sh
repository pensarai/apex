#!/bin/bash

# POC: Excessive Session Timeout - 30 Days Default Expiration
# This script demonstrates that session cookies are configured with a 30-day timeout
# which violates security best practices (recommended: 15-30 minutes)

TARGET_URL="${1:-http://localhost}"
LOGIN_ENDPOINT="${TARGET_URL}/login"
DASHBOARD_ENDPOINT="${TARGET_URL}/dashboard"

echo "=== Excessive Session Timeout POC ==="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Perform login and capture response headers
echo "[*] Step 1: Logging in and capturing Set-Cookie header..."
RESPONSE=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | head -1)

if [ -z "$SET_COOKIE" ]; then
  echo "[-] ERROR: No Set-Cookie header found in response"
  echo "Response headers:"
  echo "$RESPONSE" | head -20
  exit 1
fi

echo "[+] Set-Cookie header found:"
echo "    $SET_COOKIE"
echo ""

# Step 2: Extract expiration date
echo "[*] Step 2: Extracting expiration date..."
EXPIRES=$(echo "$SET_COOKIE" | grep -oP 'Expires=\K[^;]+')

if [ -z "$EXPIRES" ]; then
  echo "[-] ERROR: No Expires date found in Set-Cookie header"
  exit 1
fi

echo "[+] Expiration date: $EXPIRES"
echo ""

# Step 3: Convert to Unix timestamp and calculate days
echo "[*] Step 3: Calculating timeout duration..."
EXPIRES_TIMESTAMP=$(date -d "$EXPIRES" +%s 2>/dev/null)
CURRENT_TIMESTAMP=$(date +%s)
SECONDS_UNTIL_EXPIRY=$((EXPIRES_TIMESTAMP - CURRENT_TIMESTAMP))
DAYS_UNTIL_EXPIRY=$((SECONDS_UNTIL_EXPIRY / 86400))
HOURS_UNTIL_EXPIRY=$((($SECONDS_UNTIL_EXPIRY % 86400) / 3600))

echo "[+] Current Unix timestamp: $CURRENT_TIMESTAMP"
echo "[+] Expiration Unix timestamp: $EXPIRES_TIMESTAMP"
echo "[+] Seconds until expiry: $SECONDS_UNTIL_EXPIRY"
echo "[+] Days until expiry: $DAYS_UNTIL_EXPIRY days, $HOURS_UNTIL_EXPIRY hours"
echo ""

# Step 4: Check if timeout is excessive (more than 1 day)
echo "[*] Step 4: Vulnerability Assessment..."
if [ "$DAYS_UNTIL_EXPIRY" -ge 20 ]; then
  echo "[VULNERABLE] Session timeout is approximately $DAYS_UNTIL_EXPIRY days (excessive)"
  echo "    Security best practice: 15-30 minutes"
  echo "    Current setting: ~$DAYS_UNTIL_EXPIRY days"
  echo ""
  
  # Step 5: Verify session token works across the timeout period
  echo "[*] Step 5: Verifying session token is valid..."
  SESSION_COOKIE=$(echo "$SET_COOKIE" | grep -oP 'session=\K[^;]+')
  
  if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] Could not extract session cookie value"
    exit 1
  fi
  
  # Try accessing protected endpoint with the session
  PROTECTED_RESPONSE=$(curl -s -i -X GET "$DASHBOARD_ENDPOINT" \
    -H "Cookie: session=$SESSION_COOKIE" 2>&1)
  
  HTTP_CODE=$(echo "$PROTECTED_RESPONSE" | grep -m1 "HTTP" | awk '{print $2}')
  
  if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Session token is valid and grants access to protected resources"
    echo "[+] Token remains valid for ~$DAYS_UNTIL_EXPIRY days, creating extended attack window"
    echo ""
    echo "=== VULNERABILITY CONFIRMED ==="
    echo "Sessions are configured with excessive 30-day timeout period"
    echo "Attack window: ~$DAYS_UNTIL_EXPIRY days for session hijacking"
    exit 0
  else
    echo "[-] Session validation response code: $HTTP_CODE"
    echo "Could not fully validate session, but timeout is still excessive at $DAYS_UNTIL_EXPIRY days"
    exit 0
  fi
else
  echo "[-] Session timeout appears reasonable at $DAYS_UNTIL_EXPIRY days"
  exit 1
fi