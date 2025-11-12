#!/bin/bash

# POC: Brute Force Protection Test - Version 2
# This script demonstrates the absence of rate limiting and brute force protection
# by performing multiple concurrent authentication attempts

TARGET_URL="http://localhost:8080/"
ATTEMPTS=10

echo "[*] Testing for brute force protection on: $TARGET_URL"
echo "[*] Performing $ATTEMPTS concurrent authentication attempts..."
echo ""

# Counters
SUCCESS_COUNT=0
RATE_LIMIT_COUNT=0
LOCKOUT_COUNT=0

# Perform sequential requests to better observe any throttling
for i in $(seq 1 $ATTEMPTS); do
  echo "[*] Attempt $i/$ATTEMPTS: Sending request with credentials admin:wrong$i"
  
  # Send request with timing
  START_TIME=$(date +%s%N)
  RESPONSE=$(curl -s -i -u "admin:wrong$i" "$TARGET_URL" 2>&1)
  END_TIME=$(date +%s%N)
  
  # Calculate response time in milliseconds
  RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
  
  # Extract HTTP status code
  HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
  
  # Check for rate limiting indicators
  RATE_LIMIT=$(echo "$RESPONSE" | grep -i "x-ratelimit\|retry-after" | head -1)
  LOCKOUT=$(echo "$RESPONSE" | grep -i "429\|503\|too many requests" | head -1)
  
  echo "    → HTTP Status: $HTTP_CODE (Response time: ${RESPONSE_TIME}ms)"
  
  # Track results
  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then
    ((SUCCESS_COUNT++))
    echo "    → Request succeeded (no throttling)"
  fi
  
  if [ ! -z "$RATE_LIMIT" ]; then
    ((RATE_LIMIT_COUNT++))
    echo "    → Rate limit header detected: $RATE_LIMIT"
  fi
  
  if [ ! -z "$LOCKOUT" ]; then
    ((LOCKOUT_COUNT++))
    echo "    → Account lockout/429 detected"
  fi
  
  echo ""
done

echo "[*] Results Summary:"
echo "====================="
echo "[*] Total requests sent: $ATTEMPTS"
echo "[*] Successful requests (200/401): $SUCCESS_COUNT/$ATTEMPTS"
echo "[*] Responses with rate limit headers: $RATE_LIMIT_COUNT/$ATTEMPTS"
echo "[*] Responses with account lockout (429/503): $LOCKOUT_COUNT/$ATTEMPTS"
echo ""

echo "[!] VULNERABILITY ASSESSMENT:"
if [ $SUCCESS_COUNT -eq $ATTEMPTS ] && [ $RATE_LIMIT_COUNT -eq 0 ] && [ $LOCKOUT_COUNT -eq 0 ]; then
  echo "✗ NO BRUTE FORCE PROTECTION DETECTED"
  echo "  - All $ATTEMPTS requests completed successfully"
  echo "  - No rate limiting headers present"
  echo "  - No account lockout triggered"
  echo "  - No throttling or delays enforced"
  echo ""
  echo "[!] RISK: Application is vulnerable to brute force attacks"
  exit 0
else
  echo "✓ BRUTE FORCE PROTECTION DETECTED"
  echo "  - Rate limiting or account lockout is in place"
  exit 1
fi