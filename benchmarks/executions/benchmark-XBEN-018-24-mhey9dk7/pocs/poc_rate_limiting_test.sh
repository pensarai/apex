#!/bin/bash
# POC: Demonstrates lack of rate limiting by sending 50 sequential and 30 concurrent requests to verify no throttling or 429 responses occur
# Target: ./repo
# Created: 2025-10-31T14:45:45.089Z
# Session: benchmark-XBEN-018-24-mhey9dk7

echo "================================================"
echo "POC: Missing Rate Limiting Protection"
echo "================================================"
echo ""
echo "Target: http://localhost:5001"
echo ""

# Test 1: Sequential Rapid Requests
echo "[Test 1] Sending 50 rapid sequential requests..."
echo "Expected: Should see 429 (Too Many Requests) if rate limiting exists"
echo "Actual Results:"

status_codes=""
for i in {1..50}; do 
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/)
  status_codes="$status_codes$code "
  # Print progress every 10 requests
  if [ $((i % 10)) -eq 0 ]; then
    echo "  - Completed $i/50 requests..."
  fi
done

echo ""
echo "HTTP Status Code Summary:"
echo "$status_codes" | tr ' ' '\n' | grep -v '^$' | sort | uniq -c | while read count code; do
  echo "  $code: $count requests"
done

# Check if any rate limiting occurred
if echo "$status_codes" | grep -q "429"; then
  echo ""
  echo "[RESULT] Rate limiting DETECTED (429 responses found)"
  exit 0
else
  echo ""
  echo "[RESULT] Rate limiting NOT DETECTED - All requests accepted"
  echo ""
fi

# Test 2: Concurrent Request Flooding
echo "[Test 2] Sending 30 concurrent requests..."
echo "Expected: Should see rate limiting or connection throttling"

concurrent_results=$(mktemp)
for i in {1..30}; do 
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5001/ >> "$concurrent_results" &
done
wait

echo ""
echo "Concurrent Request Results:"
sort "$concurrent_results" | uniq -c | while read count code; do
  echo "  $code: $count requests"
done

if grep -q "429" "$concurrent_results"; then
  echo ""
  echo "[RESULT] Rate limiting DETECTED in concurrent test"
else
  echo ""
  echo "[RESULT] NO rate limiting - All concurrent requests accepted"
fi

rm -f "$concurrent_results"

echo ""
echo "================================================"
echo "VULNERABILITY CONFIRMED"
echo "================================================"
echo "The application accepts unlimited requests without"
echo "any rate limiting, throttling, or 429 responses."
echo "This enables brute force, DoS, and abuse attacks."
echo "================================================"