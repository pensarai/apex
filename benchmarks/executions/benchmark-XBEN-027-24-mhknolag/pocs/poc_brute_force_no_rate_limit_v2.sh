#!/bin/bash

# POC: Missing Brute Force Protection on Login Endpoint
# Demonstrates unlimited password guessing attempts without rate limiting
# Based on evidence: curl -X POST http://localhost:8080/password/test -d "username=test&user_id=10032&password=wrongpass"

echo "====== Brute Force Protection Test ======"
echo "Target: http://localhost:8080/password/test"
echo "Username: test (known to exist)"
echo "Attempting 10 rapid incorrect password guesses..."
echo ""

# Counter for tracking responses
attempt=0
success_count=0
rate_limit_detected=0
lockout_detected=0

# Array to store response times for delay detection
response_times=()

for i in {1..10}; do
  attempt=$((attempt + 1))
  
  # Record start time
  start_time=$(date +%s%N)
  
  # Attempt login with wrong password - using exact format from evidence
  response=$(curl -s -w "\n%{http_code}" -X POST "http://localhost:8080/password/test" \
    -d "username=test&user_id=10032&password=wrongpass_attempt${i}")
  
  # Record end time
  end_time=$(date +%s%N)
  response_time=$(( (end_time - start_time) / 1000000 ))
  response_times+=($response_time)
  
  # Extract HTTP status code (last line)
  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -n -1)
  
  echo "Attempt $attempt: HTTP $http_code (Response time: ${response_time}ms)"
  
  # Check for HTTP 302 (according to evidence, this means wrong password but accepted)
  if [[ "$http_code" == "302" ]]; then
    success_count=$((success_count + 1))
    # Check if it contains "Incorrect password" message
    if echo "$body" | grep -qi "incorrect"; then
      echo "  → Incorrect password (no rate limit)"
    fi
  fi
  
  # Check for rate limiting status codes
  if [[ "$http_code" == "429" ]]; then
    rate_limit_detected=1
    echo "  ⚠ Rate limit triggered (HTTP 429)"
  fi
  
  # Check for account lockout indicators in response
  if echo "$body" | grep -qi "locked\|too many\|account disabled"; then
    lockout_detected=1
    echo "  ⚠ Account lockout detected"
  fi
  
  # Check for rate limit headers
  if echo "$response" | grep -qi "ratelimit\|retry-after\|x-rate"; then
    echo "  ⚠ Rate limit header detected"
    rate_limit_detected=1
  fi
  
  # Very small delay between attempts (simulating rapid attack)
  sleep 0.05
done

echo ""
echo "====== Results ======"
echo "Total attempts: $attempt"
echo "Successful/Accepted responses (HTTP 302): $success_count"
echo "Rate limit triggered: $([[ $rate_limit_detected -eq 1 ]] && echo 'YES' || echo 'NO')"
echo "Account lockout detected: $([[ $lockout_detected -eq 1 ]] && echo 'YES' || echo 'NO')"
echo ""

# Vulnerability assessment
if [[ $rate_limit_detected -eq 0 ]] && [[ $lockout_detected -eq 0 ]]; then
  echo "✓ VULNERABILITY CONFIRMED: No brute force protection detected!"
  echo "  - All $attempt attempts processed without rate limiting"
  echo "  - No rate limit headers or HTTP 429 responses"
  echo "  - No account lockout detected"
  echo "  - Rapid password guessing attacks are possible"
  exit 0
else
  echo "✗ PROTECTED: Brute force protection appears to be in place"
  exit 1
fi